package compliance

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLinksetBuildAndQuery(t *testing.T) {
	anchor := "https://id.example.com/01/04012345678901"
	ls := NewLinkset(anchor).
		Add(LinkTypeDPP, Link{Href: "https://dpp.example/p/1", Type: "application/vc+ld+json"}).
		Add(LinkTypeCertification, Link{Href: "https://doc.example/conformity.pdf", Type: "application/pdf"})

	dpp := ls.Get(LinkTypeDPP)
	if len(dpp) != 1 || dpp[0].Href != "https://dpp.example/p/1" {
		t.Errorf("DPP link wrong: %+v", dpp)
	}
	if len(ls.LinkTypes()) != 2 {
		t.Errorf("expected 2 link types, got %d", len(ls.LinkTypes()))
	}
	if ls.Get("nonexistent") != nil {
		t.Error("missing linkType should return nil")
	}
}

func TestLinksetMultilingual(t *testing.T) {
	ls := NewLinkset("https://id.example/01/04012345678901").
		Add(LinkTypeInstructions, Link{Href: "https://x/en", HrefLang: "en"}).
		Add(LinkTypeInstructions, Link{Href: "https://x/ja", HrefLang: "ja"})
	instr := ls.Get(LinkTypeInstructions)
	if len(instr) != 2 {
		t.Fatalf("expected 2 language variants, got %d", len(instr))
	}
}

func TestLinksetMarshalRFC9264(t *testing.T) {
	ls := NewLinkset("https://id.example/01/04012345678901").
		Add(LinkTypeDPP, Link{Href: "https://dpp.example/p/1", Type: "application/vc+ld+json"})
	data, err := ls.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	// RFC 9264 structure: {"linkset":[{"anchor":...,"<linkType>":[...]}]}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["linkset"]; !ok {
		t.Error("output missing 'linkset' key")
	}
	if !strings.Contains(string(data), "anchor") {
		t.Error("output missing anchor")
	}
}

func TestLinksetMarshalNoAnchor(t *testing.T) {
	ls := &Linkset{links: map[string][]Link{}}
	if _, err := ls.MarshalJSON(); err == nil {
		t.Error("marshal without anchor should error")
	}
}

func TestLinksetRoundTrip(t *testing.T) {
	orig := NewLinkset("https://id.example/01/04012345678901").
		Add(LinkTypeDPP, Link{Href: "https://dpp.example/p/1", Type: "application/vc+ld+json", Title: "Passport"}).
		Add(LinkTypeSustainability, Link{Href: "https://x/carbon", HrefLang: "en"})

	data, err := orig.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseLinkset(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Anchor != orig.Anchor {
		t.Errorf("anchor mismatch: %q vs %q", parsed.Anchor, orig.Anchor)
	}
	dpp := parsed.Get(LinkTypeDPP)
	if len(dpp) != 1 || dpp[0].Title != "Passport" {
		t.Errorf("DPP link lost in round-trip: %+v", dpp)
	}
}

func TestParseLinksetEmpty(t *testing.T) {
	if _, err := ParseLinkset([]byte(`{"linkset":[]}`)); err == nil {
		t.Error("empty linkset should error")
	}
}

func TestParseLinksetBadJSON(t *testing.T) {
	if _, err := ParseLinkset([]byte(`{not json`)); err == nil {
		t.Error("bad JSON should error")
	}
}

func TestParseLinksetMissingAnchor(t *testing.T) {
	if _, err := ParseLinkset([]byte(`{"linkset":[{"https://gs1.org/voc/pip":[{"href":"x"}]}]}`)); err == nil {
		t.Error("missing anchor should error")
	}
}

// TestLinksetAddNilMap — Add on a zero-value Linkset (nil links map) must not panic.
func TestLinksetAddNilMap(t *testing.T) {
	ls := &Linkset{Anchor: "https://id.example/01/04012345678901"}
	ls.Add(LinkTypeDPP, Link{Href: "https://dpp.example/p/1"})
	if got := ls.Get(LinkTypeDPP); len(got) != 1 {
		t.Errorf("expected 1 link after Add on nil-map Linkset, got %d", len(got))
	}
}
