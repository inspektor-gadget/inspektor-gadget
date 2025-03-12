package formatters

import (
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/stretchr/testify/require"
)

func TestTimestampFormatterUnit(t *testing.T) {
	var tsReplacer replacer
	found := false
	for _, r := range replacers {
		if r.name == "timestamp" {
			found = true
			tsReplacer = r
			break
		}
	}
	require.True(t, found)

	ds, err := datasource.New(datasource.TypeSingle, "time", nil)
	require.NoError(t, err)
	require.NotNil(t, ds)

	fa, err := ds.AddField("timestamp_raw", api.Kind_Uint64, datasource.WithTags("type:"+ebpftypes.TimestampTypeName))
	require.NoError(t, err)
	require.NotNil(t, fa)

	lg := logger.DefaultLogger()
	randomBootTimeNs := uint64(rand.Int63n(7 * 24 * 60 * 60 * 1e9)) // Random within last 7 days
	byteSlice := make([]byte, 8)
	ds.ByteOrder().PutUint64(byteSlice, randomBootTimeNs)

	replacerFunc, err := tsReplacer.replace(lg, ds, fa)
	require.NoError(t, err)

	data, err := ds.NewPacketSingleFromRaw(byteSlice)
	require.NoError(t, err)
	require.NotNil(t, data)

	err = replacerFunc(data)
	require.NoError(t, err)

	fa = ds.GetField("timestamp")
	require.NotNil(t, fa)

	res, err := fa.String(data)
	require.NoError(t, err)
	require.Equal(t, gadgets.WallTimeFromBootTime(randomBootTimeNs).String(), res)
}

func TimestampFormatter(t *testing.T) {

	var tsField datasource.FieldAccessor

	randomBootTimeNs := uint64(rand.Int63n(7 * 24 * 60 * 60 * 1e9)) // Random within last 7 days

	Tester(
		t,
		&formattersOperator{},
		api.ParamValues{
			"operators.formatters.formatters": "timestamp",
		},
		func(gadgetCtx operators.GadgetContext) error {
			var err error
			ds, err := gadgetCtx.RegisterDataSource(datasource.TypeSingle, "time")
			require.NoError(t, err)

			// Add timestamp annotation
			tsField, err = ds.AddField("timestamp_raw", api.Kind_Uint64,
				datasource.WithTags("type:"+ebpftypes.TimestampTypeName))
			// 	datasource.WithAnnotations(map[string]string{
			// 		timestampTargetAnnotation: "formatted_timestamp",
			// 	}),
			// )
			require.NoError(t, err)
			return err
		},
		func(gadgetCtx operators.GadgetContext) error {
			ds, _ := gadgetCtx.GetDataSources()["time"]
			if ds.Type() != datasource.TypeSingle {
				return nil
			}
			data, err := ds.NewPacketSingle()
			require.NoError(t, err)

			tsField.PutUint64(data, randomBootTimeNs)

			return ds.EmitAndRelease(data)
		},
		func(gadgetCtx operators.GadgetContext) error {
			ds, _ := gadgetCtx.GetDataSources()["time"]
			if ds.Type() != datasource.TypeSingle {
				return nil
			}

			accessor := ds.GetField("timestamp")
			require.NotNil(t, accessor)

			err := ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
				res, err := accessor.String(data)

				require.NoError(t, err)
				require.Equal(t, gadgets.WallTimeFromBootTime(randomBootTimeNs).String(), res)
				return nil
			}, Priority+1)

			require.NoError(t, err)
			return nil
		},
	)
}

func Tester(
	t *testing.T,
	operator operators.DataOperator,
	paramValues api.ParamValues,
	prepare func(operators.GadgetContext) error,
	produce func(operators.GadgetContext) error,
	verify func(operators.GadgetContext) error,
) error {
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
	)

	verifier := simple.New("verifier",
		simple.WithPriority(Priority+1),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			defer wg.Done()
			defer cancel()
			return verify(gadgetCtx)
		}),
	)

	gadgetCtx := gadgetcontext.New(ctx, "",
		gadgetcontext.WithDataOperators(operator, producer, verifier),
	)

	return gadgetCtx.Run(paramValues)
}
