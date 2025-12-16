package json

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestMarshal_StringArray(t *testing.T) {
	t.Parallel()

	ds, err := datasource.New(datasource.TypeSingle, "event")
	require.NoError(t, err)

	acc, err := ds.AddField("tags", api.ArrayOf(api.Kind_String))
	require.NoError(t, err)

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)

	err = acc.PutStringArray(data, []string{"a", "b", "c"})
	require.NoError(t, err)

	formatter, err := New(ds, WithFields([]string{"tags"}))
	require.NoError(t, err)

	out := string(formatter.Marshal(data))
	require.Equal(t, `{"tags":["a","b","c"]}`, out)
}
