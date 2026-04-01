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
