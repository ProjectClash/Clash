package clash

import "testing"

func TestRunGuardedTeardownRunsStep(t *testing.T) {
	ran := false
	runGuardedTeardown(func() { ran = true })
	if !ran {
		t.Fatal("runGuardedTeardown did not run the teardown step")
	}
}

func TestRunGuardedTeardownRecoversPanic(t *testing.T) {
	escaped := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				escaped = true
			}
		}()
		runGuardedTeardown(func() { panic("boom from core teardown") })
	}()
	if escaped {
		t.Fatal("runGuardedTeardown let the panic escape the gomobile boundary")
	}
}
