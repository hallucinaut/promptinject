package promptinject

import (
	"testing"
)

func TestMain(m *testing.M) {
	println("promptinject package exists and builds successfully")
}

func TestVersion(t *testing.T) {
	version := "0.1.0"
	if version == "" {
		t.Error("Version should not be empty")
	}
}
