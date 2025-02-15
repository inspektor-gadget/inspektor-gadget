package tracer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func TestGadgetDescriptor(t *testing.T) {
	t.Parallel()

	desc := &GadgetDesc{}

	// Test Name
	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "socket", desc.Name())
	})

	// Test Category
	t.Run("Category", func(t *testing.T) {
		assert.Equal(t, gadgets.CategorySnapshot, desc.Category())
	})

	// Test Type
	t.Run("Type", func(t *testing.T) {
		assert.Equal(t, gadgets.TypeOneShot, desc.Type())
	})

	// Test Description
	t.Run("Description", func(t *testing.T) {
		assert.Equal(t, "Gather information about TCP and UDP sockets", desc.Description())
	})

	// Test EventPrototype
	t.Run("EventPrototype", func(t *testing.T) {
		event := desc.EventPrototype()
		_, ok := event.(*types.Event)
		assert.True(t, ok, "EventPrototype should return *types.Event")
	})

	// Test Parser
	t.Run("Parser", func(t *testing.T) {
		parser := desc.Parser()
		assert.NotNil(t, parser, "Parser should not be nil")
	})

	// Test SortByDefault
	t.Run("SortByDefault", func(t *testing.T) {
		expectedSort := []string{
			"k8s.node", "k8s.namespace", "k8s.podName", "protocol",
			"status", "src", "dst", "inode",
		}
		actualSort := desc.SortByDefault()
		assert.Equal(t, expectedSort, actualSort,
			"SortByDefault should return correct sorting fields")
	})

	// Test SkipParams
	t.Run("SkipParams", func(t *testing.T) {
		expectedSkip := []params.ValueHint{gadgets.K8SContainerName}
		actualSkip := desc.SkipParams()
		assert.Equal(t, expectedSkip, actualSkip,
			"SkipParams should return correct parameters to skip")
	})
}

func TestGadgetParamDescs(t *testing.T) {
	t.Parallel()

	desc := &GadgetDesc{}
	paramDescs := desc.ParamDescs()

	// Test Protocol parameter
	t.Run("Protocol Parameter", func(t *testing.T) {
		proto := findParamDesc(paramDescs, ParamProto)
		require.NotNil(t, proto, "Protocol parameter should exist")

		// Check basic parameter properties
		assert.Equal(t, "Protocol", proto.Title)
		assert.Equal(t, "all", proto.DefaultValue)

		// Verify protocol list
		assert.NotEmpty(t, proto.PossibleValues,
			"Protocol parameter should have possible values")

		// Verify that the description contains all protocols
		for _, protocol := range proto.PossibleValues {
			assert.Contains(t, proto.Description, protocol,
				"Description should mention protocol %s", protocol)
		}

		// Verify each protocol in PossibleValues exists in types.ProtocolsMap
		for _, protocol := range proto.PossibleValues {
			_, exists := types.ProtocolsMap[protocol]
			assert.True(t, exists,
				"Protocol %s from PossibleValues should exist in ProtocolsMap", protocol)
		}
	})
}

// TestValidateParams ensures parameters are validated correctly
func TestValidateParams(t *testing.T) {
	t.Parallel()

	desc := &GadgetDesc{}
	paramDescs := desc.ParamDescs()

	t.Run("ValidateProtocol", func(t *testing.T) {
		param := findParamDesc(paramDescs, ParamProto)
		require.NotNil(t, param)

		// Test default value
		assert.NoError(t, param.Validate("all"),
			"default value 'all' should be valid")

		// Test each possible value
		for _, protocol := range param.PossibleValues {
			assert.NoError(t, param.Validate(protocol),
				"protocol %s should be valid", protocol)
		}

		// Test invalid value
		assert.Error(t, param.Validate("invalid-protocol"),
			"invalid protocol should return error")
	})
}

// Helper function to find a parameter description by key
func findParamDesc(descs params.ParamDescs, key string) *params.ParamDesc {
	for i := range descs {
		if descs[i].Key == key {
			return descs[i]
		}
	}
	return nil
}
