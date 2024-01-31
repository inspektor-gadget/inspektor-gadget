package tracer

import (
	"github.com/cilium/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	tcpTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"testing"
	"time"
)

func TestConfigCreation(t *testing.T) {
	// Create a new Config object
	config := &Config{
		MountnsMap:   &ebpf.Map{},
		TargetPid:    1234,
		TargetFamily: 5678,
		MaxRows:      10,
		Interval:     time.Second * 5,
		Iterations:   3,
		SortBy:       []string{"column1", "column2"},
	}

	// Check if the Config object is created with correct values
	if config.TargetPid != 1234 {
		t.Errorf("Unexpected TargetPid, got: %d, want: %d", config.TargetPid, 1234)
	}

	if config.TargetFamily != 5678 {
		t.Errorf("Unexpected TargetFamily, got: %d, want: %d", config.TargetFamily, 5678)
	}

	if config.MaxRows != 10 {
		t.Errorf("Unexpected MaxRows, got: %d, want: %d", config.MaxRows, 10)
	}

	if config.Interval != time.Second*5 {
		t.Errorf("Unexpected Interval, got: %v, want: %v", config.Interval, time.Second*5)
	}

	if config.Iterations != 3 {
		t.Errorf("Unexpected Iterations, got: %d, want: %d", config.Iterations, 3)
	}

	if len(config.SortBy) != 2 || config.SortBy[0] != "column1" || config.SortBy[1] != "column2" {
		t.Errorf("Unexpected SortBy, got: %v, want: %v", config.SortBy, []string{"column1", "column2"})
	}
}

type MockEnricher struct{}

func (me *MockEnricher) EnrichByMntNs(event *types.CommonData, mountsnid uint64) {

}

func TestTracerCreation(t *testing.T) {
	// Create a new Config object
	config := &Config{
		// TODO Fill this with actual values
	}
	enricher := &MockEnricher{}

	callback := func(*top.Event[tcpTypes.Stats]) {}

	tracer, err := NewTracer(config, enricher, callback)
	if err != nil {
		t.Fatalf("Failed to create Tracer: %v", err)
	}

	if tracer.config != config {
		t.Errorf("Unexpected config, got: %v, want: %v", tracer.config, config)
	}

	if tracer.enricher != enricher {
		t.Errorf("Unexpected enricher, got: %v, want: %v", tracer.enricher, enricher)
	}

}
