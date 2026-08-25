// The package name matches the production package (internal/types)
// under test. revive's var-naming rule flags "types" as meaningless,
// but renaming the shared types package would ripple across every
// importer. Suppress narrowly.
//
//nolint:revive // matches the package under test; rename out of scope
package types

import "testing"

func TestVerdictConstants(t *testing.T) {
	if VerdictClean == VerdictSuspicious {
		t.Error("clean and suspicious verdicts must differ")
	}

	if VerdictClean == VerdictInconclusive {
		t.Error("clean and inconclusive verdicts must differ")
	}

	if VerdictSuspicious == VerdictInconclusive {
		t.Error("suspicious and inconclusive verdicts must differ")
	}
}
