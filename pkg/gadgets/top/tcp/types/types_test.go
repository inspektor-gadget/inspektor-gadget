package types

import (
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
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

func TestGetEndpoints(t *testing.T) {
	// Create a Stats instance
	stats := Stats{
		Pid:       1234,
		Comm:      "test",
		IPVersion: 4,
		SrcEndpoint: eventtypes.L4Endpoint{
			L3Endpoint: eventtypes.L3Endpoint{
				Addr:    "192.168.1.1",
				Version: uint8(1),
			},
			Port: 8080,
		},
		DstEndpoint: eventtypes.L4Endpoint{
			L3Endpoint: eventtypes.L3Endpoint{
				Addr:    "192.168.1.2",
				Version: uint8(1),
			},
			Port: 8080,
		},
		Sent:     1000,
		Received: 2000,
	}

	// Call the GetEndpoints method
	endpoints := stats.GetEndpoints()

	// Verify the endpoints
	if len(endpoints) != 2 {
		t.Errorf("Expected 2 endpoints, got %d", len(endpoints))
	}

	if endpoints[0].Addr != "192.168.1.1" || endpoints[0].Version != 1 {
		t.Errorf("Unexpected values for SrcEndpoint, got IP: %s, Version: %d", endpoints[0].Addr, endpoints[0].Version)
	}

	if endpoints[1].Addr != "192.168.1.2" || endpoints[1].Version != 1 {
		t.Errorf("Unexpected values for DstEndpoint, got IP: %s, Version: %d", endpoints[1].Addr, endpoints[1].Version)
	}
}
