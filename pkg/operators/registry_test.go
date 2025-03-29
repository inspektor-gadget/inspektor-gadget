package operators

import (
	"fmt"
	"sync"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type mockDataOperator struct {
	name string
}

func (m *mockDataOperator) Name() string {
	return m.name
}

func (m *mockDataOperator) Init(params *params.Params) error {
	return nil
}

func (m *mockDataOperator) Priority() int {
	return 0
}

func (m *mockDataOperator) GlobalParams() api.Params {
	return api.Params{}
}

func (m *mockDataOperator) InstanceParams() api.Params {
	return api.Params{}
}

func (m *mockDataOperator) InstantiateDataOperator(gadgetCtx GadgetContext, instanceParamValues api.ParamValues) (DataOperatorInstance, error) {
	return nil, nil
}

type mockImageOperator struct {
	name string
}

func (m *mockImageOperator) Name() string {
	return m.name
}

func (m *mockImageOperator) InstantiateImageOperator(
	gadgetCtx GadgetContext,
	target oras.ReadOnlyTarget,
	descriptor ocispec.Descriptor,
	paramValues api.ParamValues,
) (ImageOperatorInstance, error) {
	return nil, nil
}

// Test registering and retrieving data operators
func TestDataOperatorRegistry(t *testing.T) {
	// Clear the registry before test
	dataOperators = map[string]DataOperator{}

	// Create test operators
	op1 := &mockDataOperator{name: "op1"}
	op2 := &mockDataOperator{name: "op2"}

	// Test registration
	RegisterDataOperator(op1)
	RegisterDataOperator(op2)

	// Test retrieval
	ops := GetDataOperators()
	assert.Equal(t, 2, len(ops))
	assert.Equal(t, "op1", ops["op1"].Name())
	assert.Equal(t, "op2", ops["op2"].Name())

	// Test that we get a copy of the map
	delete(ops, "op1")
	ops2 := GetDataOperators()
	assert.Equal(t, 2, len(ops2), "Original map should be unchanged")
}

// Test concurrent registration of data operators
func TestConcurrentDataOperatorRegistration(t *testing.T) {
	// Clear the registry
	dataOperators = map[string]DataOperator{}

	var wg sync.WaitGroup
	numOperators := 100

	// Register operators concurrently
	for i := 0; i < numOperators; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			op := &mockDataOperator{name: fmt.Sprintf("op%d", id)}
			RegisterDataOperator(op)
		}(i)
	}

	wg.Wait()

	// Verify all operators were registered
	ops := GetDataOperators()
	assert.Equal(t, numOperators, len(ops))
}

// Test registering and retrieving image operators
func TestImageOperatorRegistry(t *testing.T) {
	// Clear the registry
	imageOperatorsByMediaType = map[string]ImageOperator{}

	// Create test operators
	op1 := &mockImageOperator{name: "img1"}
	op2 := &mockImageOperator{name: "img2"}

	// Test registration
	RegisterOperatorForMediaType("media/type1", op1)
	RegisterOperatorForMediaType("media/type2", op2)

	// Test retrieval - successful case
	retrievedOp1, exists := GetImageOperatorForMediaType("media/type1")
	require.True(t, exists)
	assert.Equal(t, "img1", retrievedOp1.Name())

	// Test retrieval - non-existent media type
	_, exists = GetImageOperatorForMediaType("non/existent")
	assert.False(t, exists)
}

// Test concurrent registration of image operators
func TestConcurrentImageOperatorRegistration(t *testing.T) {
	// Clear the registry
	imageOperatorsByMediaType = map[string]ImageOperator{}

	var wg sync.WaitGroup
	numOperators := 100

	// Register operators concurrently
	for i := 0; i < numOperators; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			op := &mockImageOperator{name: fmt.Sprintf("img%d", id)}
			mediaType := fmt.Sprintf("media/type%d", id)
			RegisterOperatorForMediaType(mediaType, op)
		}(i)
	}

	wg.Wait()

	// Verify random sample of operators were registered correctly
	for i := 0; i < 10; i++ {
		mediaType := fmt.Sprintf("media/type%d", i)
		op, exists := GetImageOperatorForMediaType(mediaType)
		require.True(t, exists)
		assert.Equal(t, fmt.Sprintf("img%d", i), op.Name())
	}
}

// Test overwriting existing operators
func TestOperatorOverwrite(t *testing.T) {
	// Clear registries
	dataOperators = map[string]DataOperator{}
	imageOperatorsByMediaType = map[string]ImageOperator{}

	// Test data operator overwrite
	op1 := &mockDataOperator{name: "test"}
	op2 := &mockDataOperator{name: "test"}
	RegisterDataOperator(op1)
	RegisterDataOperator(op2)
	ops := GetDataOperators()
	assert.Equal(t, 1, len(ops))

	// Test image operator overwrite
	imgOp1 := &mockImageOperator{name: "img1"}
	imgOp2 := &mockImageOperator{name: "img2"}
	mediaType := "media/type"
	RegisterOperatorForMediaType(mediaType, imgOp1)
	RegisterOperatorForMediaType(mediaType, imgOp2)
	op, exists := GetImageOperatorForMediaType(mediaType)
	require.True(t, exists)
	assert.Equal(t, "img2", op.Name())
}
