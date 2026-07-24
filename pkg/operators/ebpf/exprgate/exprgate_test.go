// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exprgate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKallsyms(present ...string) KallsymsFuncs {
	set := make(map[string]bool, len(present))
	for _, s := range present {
		set[s] = true
	}
	exists := func(s string) bool { return set[s] }
	return KallsymsFuncs{
		Exists: exists,
		First: func(syms ...string) (string, error) {
			for _, s := range syms {
				if set[s] {
					return s, nil
				}
			}
			return "", errNoSymbol(syms)
		},
	}
}

func errNoSymbol(syms []string) error {
	return &noSymbolError{syms}
}

type noSymbolError struct{ syms []string }

func (e *noSymbolError) Error() string { return "no candidate symbol exists" }

func TestOnlyIf(t *testing.T) {
	e := New(nil, testKallsyms())

	tests := []struct {
		name   string
		expr   string
		params map[string]any
		want   bool
	}{
		{"single true", "params.collect_ustack", map[string]any{"collect_ustack": true}, true},
		{"single false", "params.collect_ustack", map[string]any{"collect_ustack": false}, false},
		{"and true", "params.a && params.b", map[string]any{"a": true, "b": true}, true},
		{"and false", "params.a && params.b", map[string]any{"a": true, "b": false}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := e.Compile(tt.expr, KindOnlyIf, "")
			require.NoError(t, err)
			got, err := e.EvalBool(p, tt.params, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestOnlyIfRejectsKallsyms(t *testing.T) {
	e := New(nil, testKallsyms("sym"))
	// kallsyms.* must not be visible in an only_if expression.
	_, err := e.Compile("kallsyms.exists('sym')", KindOnlyIf, "")
	require.Error(t, err)
}

func TestOnlyIfNonBool(t *testing.T) {
	e := New(nil, testKallsyms())
	// A string result must fail (either at compile via AsBool or at eval).
	p, err := e.Compile("params.name", KindOnlyIf, "")
	if err != nil {
		return // rejected at compile, acceptable
	}
	_, err = e.EvalBool(p, map[string]any{"name": "x"}, nil)
	require.Error(t, err)
}

func TestAttachTo(t *testing.T) {
	e := New(nil, testKallsyms("inotify_handle_inode_event", "fsnotify_insert_event"))

	tests := []struct {
		name string
		expr string
		want string
	}{
		{
			"exists true",
			"kallsyms.exists('inotify_handle_inode_event') ? 'inotify_handle_inode_event' : program.disabled",
			"inotify_handle_inode_event",
		},
		{
			"exists false disables",
			"kallsyms.exists('missing') ? 'missing' : program.disabled",
			ProgramDisabled,
		},
		{
			"first match",
			"kallsyms.first('missing', 'fsnotify_insert_event', 'fsnotify_add_event')",
			"fsnotify_insert_event",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := e.Compile(tt.expr, KindAttachTo, "")
			require.NoError(t, err)
			got, err := e.EvalString(p, nil, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAttachToFirstNoMatchErrors(t *testing.T) {
	e := New(nil, testKallsyms())
	p, err := e.Compile("kallsyms.first('a', 'b')", KindAttachTo, "")
	require.NoError(t, err)
	_, err = e.EvalString(p, nil, nil)
	require.Error(t, err)
}

func TestAssert(t *testing.T) {
	e := New(nil, testKallsyms())

	p, err := e.Compile("!(params.inotify_only && params.fanotify_only)", KindAssert, "")
	require.NoError(t, err)

	ok, err := e.EvalBool(p, map[string]any{"inotify_only": true, "fanotify_only": false}, nil)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = e.EvalBool(p, map[string]any{"inotify_only": true, "fanotify_only": true}, nil)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestAssertEnumMembership(t *testing.T) {
	e := New(nil, testKallsyms())
	p, err := e.Compile("params.target_family in [-1, 4, 6]", KindAssert, "")
	require.NoError(t, err)

	ok, err := e.EvalBool(p, map[string]any{"target_family": int64(-1)}, nil)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = e.EvalBool(p, map[string]any{"target_family": int64(5)}, nil)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestDefineScalar(t *testing.T) {
	e := New([]string{"has_insert"}, testKallsyms("fsnotify_insert_event"))

	def, err := e.Compile("kallsyms.exists('fsnotify_insert_event')", KindDefine, "has_insert")
	require.NoError(t, err)
	v, err := e.EvalAny(def, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, true, v)

	// A later attach_to can reference the define.
	p, err := e.Compile("has_insert ? 'fsnotify_insert_event' : program.disabled", KindAttachTo, "")
	require.NoError(t, err)
	got, err := e.EvalString(p, nil, map[string]any{"has_insert": v})
	require.NoError(t, err)
	assert.Equal(t, "fsnotify_insert_event", got)
}

func TestDefineTable(t *testing.T) {
	e := New([]string{"fs"}, testKallsyms())

	defExpr := "let table = {" +
		"'ext4': {read: 'ext4_file_read_iter', open: 'ext4_file_open'}," +
		"'btrfs': {read: 'btrfs_file_read_iter', open: 'btrfs_file_open'}" +
		"}; " +
		"let disabled = {read: program.disabled, open: program.disabled}; " +
		"params.filesystem in table ? table[params.filesystem] : disabled"

	def, err := e.Compile(defExpr, KindDefine, "fs")
	require.NoError(t, err)

	fsVal, err := e.EvalAny(def, map[string]any{"filesystem": "ext4"}, nil)
	require.NoError(t, err)

	read, err := e.Compile("fs.read", KindAttachTo, "")
	require.NoError(t, err)
	got, err := e.EvalString(read, map[string]any{"filesystem": "ext4"}, map[string]any{"fs": fsVal})
	require.NoError(t, err)
	assert.Equal(t, "ext4_file_read_iter", got)

	// Unsupported filesystem falls back to the disabled row.
	fsVal2, err := e.EvalAny(def, map[string]any{"filesystem": "zfs"}, nil)
	require.NoError(t, err)
	got2, err := e.EvalString(read, map[string]any{"filesystem": "zfs"}, map[string]any{"fs": fsVal2})
	require.NoError(t, err)
	assert.Equal(t, ProgramDisabled, got2)
}

func TestDefineForwardReferenceFails(t *testing.T) {
	e := New([]string{"first_def", "second_def"}, testKallsyms())
	// first_def may not reference second_def (declared later).
	_, err := e.Compile("second_def", KindDefine, "first_def")
	require.Error(t, err)
}

func TestCompileErrorUnknownIdentifier(t *testing.T) {
	e := New(nil, testKallsyms())
	_, err := e.Compile("nonexistent.thing", KindAttachTo, "")
	require.Error(t, err)
}
