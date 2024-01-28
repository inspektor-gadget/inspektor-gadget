package types

import (
	"syscall"
	"testing"
)

func TestTracer(t *testing.T) {
	//skip test but log
	t.Skip("skip test but log tcp/types")
}

func TestParseFilterByFamilyPassing(t *testing.T) {
	t.Log("something")
	family := "4"
	expected := syscall.AF_INET
	result, err := ParseFilterByFamily(family)
	if err != nil {
		t.Fatalf("ParseFilterByFamily returned an error: %v", err)
	}
	if result != int32(expected) {
		t.Errorf("ParseFilterByFamily was incorrect, got: %d, want: %d.", result, expected)
	}
}

func TestParseFilterByFamilyFailing(t *testing.T) {
	t.Log("something")
	family := "5"
	_, err := ParseFilterByFamily(family)
	if err == nil {
		t.Fatalf("ParseFilterByFamily didn't return an error")
	}
}
