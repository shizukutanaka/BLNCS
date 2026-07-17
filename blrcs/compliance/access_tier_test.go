package compliance

import (
	"testing"
	"time"
)

func TestAccessTierValidity(t *testing.T) {
	for _, tier := range []AccessTier{TierPublic, TierRestricted, TierAuthority} {
		if !tier.IsValid() {
			t.Errorf("%s should be valid", tier)
		}
	}
	if AccessTier("bogus").IsValid() {
		t.Error("bogus tier should be invalid")
	}
}

func TestAccessTierRanking(t *testing.T) {
	if TierPublic.rank() >= TierRestricted.rank() {
		t.Error("public should rank below restricted")
	}
	if TierRestricted.rank() >= TierAuthority.rank() {
		t.Error("restricted should rank below authority")
	}
	if AccessTier("bogus").rank() != -1 {
		t.Error("invalid tier rank should be -1")
	}
}

func TestTieredClaimsSetAndGet(t *testing.T) {
	tc := NewTieredClaims().
		Set("carbonKgCO2e", 12.5, TierPublic).
		Set("materialComposition", "NMC811", TierRestricted).
		Set("supplierContract", "secret", TierAuthority)

	tier, ok := tc.Tier("carbonKgCO2e")
	if !ok || tier != TierPublic {
		t.Errorf("carbon tier: %v %v", tier, ok)
	}
	if _, ok := tc.Tier("nonexistent"); ok {
		t.Error("missing key should report not-found")
	}
}

// TestTieredClaimsInvalidTierFailsafe verifies that an unrecognised tier string
// falls to TierAuthority (the most restrictive tier), not TierRestricted.
// Before the fix, invalid tiers defaulted to TierRestricted, so a developer
// typo like AccessTier("Authority") (wrong case) could silently expose
// authority-only supply-chain secrets to recyclers (TierRestricted viewers).
// The secure-by-default direction is always toward maximum restriction.
func TestTieredClaimsInvalidTierFailsafe(t *testing.T) {
	for _, badTier := range []AccessTier{"bogus", "Authority", "PUBLIC", "", "RESTRICTED"} {
		tc := NewTieredClaims().Set("x", 1, badTier)
		tier, _ := tc.Tier("x")
		if tier != TierAuthority {
			t.Errorf("invalid tier %q should fail secure to authority, got %s", badTier, tier)
		}
	}
}

// TestTieredClaimsInvalidTierNotExposedToRestricted confirms that a claim
// stored under an invalid tier is NOT accessible at TierRestricted level —
// only at TierAuthority level — after the secure-default fix.
func TestTieredClaimsInvalidTierNotExposedToRestricted(t *testing.T) {
	tc := NewTieredClaims().Set("secret", "supplierContract", AccessTier("bogus"))

	// Restricted viewer must NOT see the claim.
	resView := tc.ClaimsAtOrBelow(TierRestricted)
	if resView["secret"] != nil {
		t.Error("invalid-tier claim must not be visible to TierRestricted viewer")
	}

	// Authority viewer must see it (claim is still stored and accessible).
	authView := tc.ClaimsAtOrBelow(TierAuthority)
	if authView["secret"] == nil {
		t.Error("invalid-tier claim should be visible to TierAuthority viewer")
	}
}

func TestTieredClaimsKeysSorted(t *testing.T) {
	tc := NewTieredClaims().
		Set("zebra", 1, TierPublic).
		Set("alpha", 2, TierPublic).
		Set("mango", 3, TierPublic)
	keys := tc.Keys()
	if len(keys) != 3 || keys[0] != "alpha" || keys[2] != "zebra" {
		t.Errorf("keys not sorted: %v", keys)
	}
}

func TestClaimsAtOrBelow(t *testing.T) {
	tc := NewTieredClaims().
		Set("pub", 1, TierPublic).
		Set("res", 2, TierRestricted).
		Set("auth", 3, TierAuthority)

	// Public viewer sees only public
	pubView := tc.ClaimsAtOrBelow(TierPublic)
	if len(pubView) != 1 || pubView["pub"] == nil {
		t.Errorf("public view wrong: %v", pubView)
	}
	// Restricted viewer sees public + restricted
	resView := tc.ClaimsAtOrBelow(TierRestricted)
	if len(resView) != 2 {
		t.Errorf("restricted view should have 2, got %d", len(resView))
	}
	if resView["auth"] != nil {
		t.Error("restricted viewer must not see authority data")
	}
	// Authority viewer sees all
	authView := tc.ClaimsAtOrBelow(TierAuthority)
	if len(authView) != 3 {
		t.Errorf("authority view should have all 3, got %d", len(authView))
	}
}

func TestSplitForSDJWT(t *testing.T) {
	tc := NewTieredClaims().
		Set("carbon", 12.5, TierPublic).
		Set("recycledContent", 0.3, TierPublic).
		Set("materialComposition", "NMC", TierRestricted).
		Set("contract", "x", TierAuthority)

	clear, sd := tc.SplitForSDJWT()
	// public → clear
	if len(clear) != 2 {
		t.Errorf("expected 2 clear claims, got %d", len(clear))
	}
	if clear["carbon"] == nil {
		t.Error("public carbon should be in clear claims")
	}
	// restricted + authority → SD
	if len(sd) != 2 {
		t.Errorf("expected 2 SD claims, got %d", len(sd))
	}
	if sd["materialComposition"] == nil || sd["contract"] == nil {
		t.Error("restricted/authority should be in SD claims")
	}
}

func TestIssueSDJWTTiered(t *testing.T) {
	iss, _ := NewIssuer("did:web:tiered.test")
	tc := NewTieredClaims().
		Set("carbonKgCO2ePerKWh", 12.5, TierPublic).
		Set("materialComposition", "NMC811", TierRestricted)

	sdjwt, disclosures, err := iss.IssueSDJWTTiered("battery-123", tc, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Public claim is always present (clear); restricted is a disclosure
	if len(disclosures) != 1 {
		t.Errorf("expected 1 disclosure (restricted), got %d", len(disclosures))
	}

	// The issued SD-JWT bundles all disclosures (issuer→holder form).
	// Public claim is in the clear payload; restricted is a disclosure.
	vc, err := VerifySDJWT(sdjwt, iss.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if vc.Claims["carbonKgCO2ePerKWh"] == nil {
		t.Error("public carbon claim should be visible")
	}
	if vc.VCT != VCTDigitalProductPassport {
		t.Errorf("vct: %s", vc.VCT)
	}

	// A holder presenting ONLY public data withholds the restricted disclosure.
	publicOnly, err := Present(sdjwt, []string{})
	if err != nil {
		t.Fatal(err)
	}
	vcPub, err := VerifySDJWT(publicOnly, iss.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if vcPub.Claims["carbonKgCO2ePerKWh"] == nil {
		t.Error("public claim must survive a public-only presentation")
	}
	if vcPub.Claims["materialComposition"] != nil {
		t.Error("restricted claim must be withheld when not presented")
	}
}

func TestIssueSDJWTTieredAllPublic(t *testing.T) {
	iss, _ := NewIssuer("did:web:tiered.test")
	tc := NewTieredClaims().
		Set("a", 1, TierPublic).
		Set("b", 2, TierPublic)
	_, disclosures, err := iss.IssueSDJWTTiered("subj", tc, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(disclosures) != 0 {
		t.Errorf("all-public should yield no disclosures, got %d", len(disclosures))
	}
}
