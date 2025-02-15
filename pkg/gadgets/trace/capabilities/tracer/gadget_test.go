package tracer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func TestGadgetDescriptor(t *testing.T) {
	t.Parallel()

	desc := &GadgetDesc{}

	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "capabilities", desc.Name())
	})

	t.Run("Category", func(t *testing.T) {
		assert.Equal(t, gadgets.CategoryTrace, desc.Category())
	})

	t.Run("Type", func(t *testing.T) {
		assert.Equal(t, gadgets.TypeTrace, desc.Type())
	})

	t.Run("Description", func(t *testing.T) {
		assert.Equal(t, "Trace security capability checks", desc.Description())
	})

	t.Run("EventPrototype", func(t *testing.T) {
		event := desc.EventPrototype()
		_, ok := event.(*types.Event)
		assert.True(t, ok, "EventPrototype should return *types.Event")
	})

	t.Run("Parser", func(t *testing.T) {
		parser := desc.Parser()
		assert.NotNil(t, parser, "Parser should not be nil")
	})
}

func TestGadgetParamDescs(t *testing.T) {
	t.Parallel()

	desc := &GadgetDesc{}
	paramDescs := desc.ParamDescs()

	t.Run("AuditOnly Parameter", func(t *testing.T) {
		auditOnly := findParamDesc(paramDescs, ParamAuditOnly)
		require.NotNil(t, auditOnly, "AuditOnly parameter should exist")
		assert.Equal(t, "Audit Only", auditOnly.Title)
		assert.Equal(t, "true", auditOnly.DefaultValue)
		assert.Equal(t, params.TypeBool, auditOnly.TypeHint)
		assert.Equal(t, "Only show audit checks", auditOnly.Description)
	})

	t.Run("Unique Parameter", func(t *testing.T) {
		unique := findParamDesc(paramDescs, ParamUnique)
		require.NotNil(t, unique, "Unique parameter should exist")
		assert.Equal(t, "Unique", unique.Title)
		assert.Equal(t, "false", unique.DefaultValue)
		assert.Equal(t, params.TypeBool, unique.TypeHint)
		assert.Equal(t, "Only show a capability once on the same container", unique.Description)
	})
}

func TestValidateParams(t *testing.T) {
	t.Parallel()

	desc := &GadgetDesc{}
	paramDescs := desc.ParamDescs()

	t.Run("ValidateAuditOnly", func(t *testing.T) {
		param := findParamDesc(paramDescs, ParamAuditOnly)
		require.NotNil(t, param)

		assert.NoError(t, param.Validate("true"), "true should be valid")
		assert.NoError(t, param.Validate("false"), "false should be valid")

		assert.Error(t, param.Validate("invalid"), "non-boolean should be invalid")
	})

	t.Run("ValidateUnique", func(t *testing.T) {
		param := findParamDesc(paramDescs, ParamUnique)
		require.NotNil(t, param)

		assert.NoError(t, param.Validate("true"), "true should be valid")
		assert.NoError(t, param.Validate("false"), "false should be valid")

		assert.Error(t, param.Validate("invalid"), "non-boolean should be invalid")
	})
}

func findParamDesc(descs params.ParamDescs, key string) *params.ParamDesc {
	for i := range descs {
		if descs[i].Key == key {
			return descs[i]
		}
	}
	return nil
}
