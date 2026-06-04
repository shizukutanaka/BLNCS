package apispec

import (
	"testing"
)

func TestSymbolFullName(t *testing.T) {
	s := Symbol{Package: "blrcs/compliance", Name: "Issue"}
	if s.FullName() != "blrcs/compliance.Issue" {
		t.Errorf("fullname: %s", s.FullName())
	}
}

func TestRegistryRoundTrip(t *testing.T) {
	r := NewRegistry()
	s := Symbol{Package: "p", Name: "F", Stability: Stable, IntroducedIn: "1.0.0"}
	r.Register(s)
	got, ok := r.Get(s.FullName())
	if !ok {
		t.Fatal("not found after register")
	}
	if got.Stability != Stable {
		t.Errorf("stability: %s", got.Stability)
	}
}

func TestRegistryAllSorted(t *testing.T) {
	r := NewRegistry()
	r.Register(Symbol{Package: "z", Name: "Y"})
	r.Register(Symbol{Package: "a", Name: "Z"})
	r.Register(Symbol{Package: "a", Name: "A"})
	all := r.All()
	if len(all) != 3 {
		t.Fatalf("count: %d", len(all))
	}
	// Sorted by package, then name
	if all[0].Package != "a" || all[0].Name != "A" {
		t.Errorf("first: %+v", all[0])
	}
	if all[1].Package != "a" || all[1].Name != "Z" {
		t.Errorf("second: %+v", all[1])
	}
	if all[2].Package != "z" {
		t.Errorf("third: %+v", all[2])
	}
}

func TestFilterByStability(t *testing.T) {
	r := NewRegistry()
	r.Register(Symbol{Package: "p", Name: "A", Stability: Stable})
	r.Register(Symbol{Package: "p", Name: "B", Stability: Beta})
	r.Register(Symbol{Package: "p", Name: "C", Stability: Stable})
	stable := r.FilterByStability(Stable)
	if len(stable) != 2 {
		t.Errorf("stable count: %d", len(stable))
	}
	beta := r.FilterByStability(Beta)
	if len(beta) != 1 {
		t.Errorf("beta count: %d", len(beta))
	}
}

func TestSymbolIsRetired(t *testing.T) {
	s := Symbol{
		Package:     "p",
		Name:        "Old",
		Stability:   Deprecated,
		RemoveAfter: "2.0.0",
	}
	if s.IsRetired("1.5.0") {
		t.Error("should not be retired in 1.5.0")
	}
	if !s.IsRetired("2.0.0") {
		t.Error("should be retired in 2.0.0")
	}
	if !s.IsRetired("3.0.0") {
		t.Error("should be retired in 3.0.0")
	}
}

func TestSymbolNoRemoveAfter(t *testing.T) {
	s := Symbol{Package: "p", Name: "X", Stability: Stable}
	if s.IsRetired("99.0.0") {
		t.Error("Stable symbol should never be retired")
	}
}

func TestDueForRemoval(t *testing.T) {
	r := NewRegistry()
	r.Register(Symbol{Package: "p", Name: "Old1", Stability: Deprecated, RemoveAfter: "1.0.0"})
	r.Register(Symbol{Package: "p", Name: "Old2", Stability: Deprecated, RemoveAfter: "2.0.0"})
	r.Register(Symbol{Package: "p", Name: "Stay", Stability: Deprecated, RemoveAfter: "5.0.0"})

	due := r.DueForRemoval("2.0.0")
	if len(due) != 2 {
		t.Errorf("due count at 2.0.0: %d (want 2)", len(due))
	}
}

func TestSemverGTE(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.0.0", "1.0.0", true},
		{"1.0.1", "1.0.0", true},
		{"1.0.0", "1.0.1", false},
		{"2.0.0", "1.99.99", true},
		{"1.5.0", "1.4.99", true},
		{"0.1.0", "0.0.99", true},
	}
	for _, c := range cases {
		if got := semverGTE(c.a, c.b); got != c.want {
			t.Errorf("semverGTE(%q,%q): got=%v want=%v", c.a, c.b, got, c.want)
		}
	}
}

func TestDeclareDeprecatedAutoRunway(t *testing.T) {
	Reset()
	defer Reset()
	DeclareDeprecated("p", "OldFn", "1.5.0", "p.NewFn", "https://docs/migrate")
	got, ok := Default().Get("p.OldFn")
	if !ok {
		t.Fatal("not registered")
	}
	if got.Stability != Deprecated {
		t.Errorf("stability: %s", got.Stability)
	}
	if got.RemoveAfter != "2.0.0" {
		t.Errorf("auto-runway: removeAfter=%s want 2.0.0", got.RemoveAfter)
	}
	if got.ReplacedBy != "p.NewFn" {
		t.Errorf("replacedBy: %s", got.ReplacedBy)
	}
	if got.DeprecatedAt.IsZero() {
		t.Error("deprecatedAt not set")
	}
}

func TestDeclareStable(t *testing.T) {
	Reset()
	defer Reset()
	DeclareStable("p", "X", "func", "1.0.0")
	got, ok := Default().Get("p.X")
	if !ok {
		t.Fatal("not registered")
	}
	if got.Stability != Stable {
		t.Errorf("stability: %s", got.Stability)
	}
	if got.Kind != "func" {
		t.Errorf("kind: %s", got.Kind)
	}
}
