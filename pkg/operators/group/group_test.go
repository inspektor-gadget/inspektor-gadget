// Copyright 2025 The Inspektor Gadget authors
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

// Package group is a data operator that groups entries in an array datasource
// based on specified fields and aggregates the remaining fields according to
// field annotations.
package group

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestGroupBasic(t *testing.T) {
	// Create a datasource with fields
	ds, err := datasource.New(datasource.TypeArray, "group")
	require.NoError(t, err)

	// Add fields to the datasource
	categoryField, err := ds.AddField("category", api.Kind_String)
	require.NoError(t, err)

	valueField, err := ds.AddField("value", api.Kind_Int64)
	require.NoError(t, err)

	// Create test data
	data, err := ds.NewPacketArray()
	require.NoError(t, err)

	// Add entries with different categories and values
	// Category A: values 10, 20, 30 (sum = 60)
	// Category B: values 5, 15 (sum = 20)
	testData := []struct {
		category string
		value    int64
	}{
		{"A", 10},
		{"A", 20},
		{"A", 30},
		{"B", 5},
		{"B", 15},
	}

	for _, td := range testData {
		entry := data.New()
		categoryField.PutString(entry, td.category)
		valueField.PutInt64(entry, td.value)
		data.Append(entry)
	}

	// Test grouping by category
	err = groupFn(ds, data, []string{"category"})
	require.NoError(t, err)

	// After grouping, we should have 2 entries (one for each category)
	require.Equal(t, 2, data.Len())

	// Verify the grouped data
	// The entries should be sorted by their original indices, so A comes before B
	entry0 := data.Get(0)
	category0, err := categoryField.String(entry0)
	require.NoError(t, err)
	value0, err := valueField.Int64(entry0)
	require.NoError(t, err)

	entry1 := data.Get(1)
	category1, err := categoryField.String(entry1)
	require.NoError(t, err)
	value1, err := valueField.Int64(entry1)
	require.NoError(t, err)

	// Check that we have one entry for each category
	require.Equal(t, "A", category0)
	require.Equal(t, "B", category1)

	// Check that numeric values were summed (default aggregation for numeric fields)
	require.Equal(t, int64(60), value0) // 10 + 20 + 30
	require.Equal(t, int64(20), value1) // 5 + 15
}

func TestGroupAggregationMethods(t *testing.T) {
	// Create a datasource with fields
	ds, err := datasource.New(datasource.TypeArray, "group")
	require.NoError(t, err)

	// Add fields to the datasource
	categoryField, err := ds.AddField("category", api.Kind_String)
	require.NoError(t, err)

	// Add numeric fields with different aggregation methods
	sumField, err := ds.AddField("sum_value", api.Kind_Int64)
	require.NoError(t, err)
	sumField.AddAnnotation(AnnotationAggregation, AggregationSum)

	minField, err := ds.AddField("min_value", api.Kind_Int64)
	require.NoError(t, err)
	minField.AddAnnotation(AnnotationAggregation, AggregationMin)

	maxField, err := ds.AddField("max_value", api.Kind_Int64)
	require.NoError(t, err)
	maxField.AddAnnotation(AnnotationAggregation, AggregationMax)

	avgField, err := ds.AddField("avg_value", api.Kind_Int64)
	require.NoError(t, err)
	avgField.AddAnnotation(AnnotationAggregation, AggregationAvg)

	firstField, err := ds.AddField("first_value", api.Kind_Int64)
	require.NoError(t, err)
	firstField.AddAnnotation(AnnotationAggregation, AggregationFirst)

	lastField, err := ds.AddField("last_value", api.Kind_Int64)
	require.NoError(t, err)
	lastField.AddAnnotation(AnnotationAggregation, AggregationLast)

	// Add string fields with different aggregation methods
	firstStrField, err := ds.AddField("first_str", api.Kind_String)
	require.NoError(t, err)
	firstStrField.AddAnnotation(AnnotationAggregation, AggregationFirst)

	lastStrField, err := ds.AddField("last_str", api.Kind_String)
	require.NoError(t, err)
	lastStrField.AddAnnotation(AnnotationAggregation, AggregationLast)

	concatField, err := ds.AddField("concat_str", api.Kind_String)
	require.NoError(t, err)
	concatField.AddAnnotation(AnnotationAggregation, AggregationConcat)
	concatField.AddAnnotation(AnnotationSeparator, ", ")

	// Create test data
	data, err := ds.NewPacketArray()
	require.NoError(t, err)

	// Add entries with the same category but different values
	testData := []struct {
		category string
		value    int64
		strValue string
	}{
		{"A", 10, "first"},
		{"A", 5, "second"},
		{"A", 20, "third"},
	}

	for _, td := range testData {
		entry := data.New()
		categoryField.PutString(entry, td.category)

		// Set all numeric fields to the same value for this entry
		sumField.PutInt64(entry, td.value)
		minField.PutInt64(entry, td.value)
		maxField.PutInt64(entry, td.value)
		avgField.PutInt64(entry, td.value)
		firstField.PutInt64(entry, td.value)
		lastField.PutInt64(entry, td.value)

		// Set all string fields to the same value for this entry
		firstStrField.PutString(entry, td.strValue)
		lastStrField.PutString(entry, td.strValue)
		concatField.PutString(entry, td.strValue)

		data.Append(entry)
	}

	// Test grouping by category
	err = groupFn(ds, data, []string{"category"})
	require.NoError(t, err)

	// After grouping, we should have 1 entry (all entries have the same category)
	require.Equal(t, 1, data.Len())

	// Verify the aggregated values
	entry := data.Get(0)

	// Check numeric field aggregations
	sumValue, err := sumField.Int64(entry)
	require.NoError(t, err)
	require.Equal(t, int64(35), sumValue) // 10 + 5 + 20

	minValue, err := minField.Int64(entry)
	require.NoError(t, err)
	require.Equal(t, int64(5), minValue) // min of 10, 5, 20

	maxValue, err := maxField.Int64(entry)
	require.NoError(t, err)
	require.Equal(t, int64(20), maxValue) // max of 10, 5, 20

	avgValue, err := avgField.Int64(entry)
	require.NoError(t, err)
	require.Equal(t, int64(11), avgValue) // (10 + 5 + 20) / 3 = 11.66, truncated to 11

	firstValue, err := firstField.Int64(entry)
	require.NoError(t, err)
	require.Equal(t, int64(10), firstValue) // first value is 10

	lastValue, err := lastField.Int64(entry)
	require.NoError(t, err)
	require.Equal(t, int64(20), lastValue) // last value is 20

	// Check string field aggregations
	firstStr, err := firstStrField.String(entry)
	require.NoError(t, err)
	require.Equal(t, "first", firstStr) // first string

	lastStr, err := lastStrField.String(entry)
	require.NoError(t, err)
	require.Equal(t, "third", lastStr) // last string

	concatStr, err := concatField.String(entry)
	require.NoError(t, err)
	require.Equal(t, "first, second, third", concatStr) // concatenated strings
}

func TestGroupMultipleFields(t *testing.T) {
	// Create a datasource with fields
	ds, err := datasource.New(datasource.TypeArray, "group")
	require.NoError(t, err)

	// Add fields to the datasource
	categoryField, err := ds.AddField("category", api.Kind_String)
	require.NoError(t, err)

	subCategoryField, err := ds.AddField("subcategory", api.Kind_String)
	require.NoError(t, err)

	valueField, err := ds.AddField("value", api.Kind_Int64)
	require.NoError(t, err)

	// Create test data
	data, err := ds.NewPacketArray()
	require.NoError(t, err)

	// Add entries with different categories, subcategories, and values
	testData := []struct {
		category    string
		subcategory string
		value       int64
	}{
		{"A", "X", 10},
		{"A", "X", 20},
		{"A", "Y", 30},
		{"A", "Y", 40},
		{"B", "X", 50},
		{"B", "X", 60},
	}

	for _, td := range testData {
		entry := data.New()
		categoryField.PutString(entry, td.category)
		subCategoryField.PutString(entry, td.subcategory)
		valueField.PutInt64(entry, td.value)
		data.Append(entry)
	}

	// Test grouping by category and subcategory
	err = groupFn(ds, data, []string{"category", "subcategory"})
	require.NoError(t, err)

	// After grouping, we should have 3 entries (A-X, A-Y, B-X)
	require.Equal(t, 3, data.Len())

	// Verify the grouped data
	// The entries should be sorted by their original indices
	// Check each group's values
	for i := 0; i < data.Len(); i++ {
		entry := data.Get(i)
		category, err := categoryField.String(entry)
		require.NoError(t, err)
		subcategory, err := subCategoryField.String(entry)
		require.NoError(t, err)
		value, err := valueField.Int64(entry)
		require.NoError(t, err)

		switch {
		case category == "A" && subcategory == "X":
			require.Equal(t, int64(30), value) // 10 + 20
		case category == "A" && subcategory == "Y":
			require.Equal(t, int64(70), value) // 30 + 40
		case category == "B" && subcategory == "X":
			require.Equal(t, int64(110), value) // 50 + 60
		default:
			t.Errorf("Unexpected group: category=%s, subcategory=%s", category, subcategory)
		}
	}
}

func TestGroupEmptyArray(t *testing.T) {
	// Create a datasource with fields
	ds, err := datasource.New(datasource.TypeArray, "group")
	require.NoError(t, err)

	// Add fields to the datasource
	_, err = ds.AddField("category", api.Kind_String)
	require.NoError(t, err)

	_, err = ds.AddField("value", api.Kind_Int64)
	require.NoError(t, err)

	// Create an empty array
	data, err := ds.NewPacketArray()
	require.NoError(t, err)

	// Test grouping on empty array
	err = groupFn(ds, data, []string{"category"})
	require.NoError(t, err)

	// Array should still be empty
	require.Equal(t, 0, data.Len())
}

func TestGroupInvalidField(t *testing.T) {
	// This test verifies that the groupFn function handles invalid field names properly
	// Note: The actual validation of field names happens in the PreStart method of groupOperatorInstance,
	// but we can still test how groupFn handles missing fields

	// Create a datasource with fields
	ds, err := datasource.New(datasource.TypeArray, "group")
	require.NoError(t, err)

	// Add a field to the datasource
	categoryField, err := ds.AddField("category", api.Kind_String)
	require.NoError(t, err)

	valueField, err := ds.AddField("value", api.Kind_Int64)
	require.NoError(t, err)

	// Create test data
	data, err := ds.NewPacketArray()
	require.NoError(t, err)

	// Add a few entries
	entry := data.New()
	categoryField.PutString(entry, "A")
	valueField.PutInt64(entry, 10)
	data.Append(entry)

	entry = data.New()
	categoryField.PutString(entry, "B")
	valueField.PutInt64(entry, 20)
	data.Append(entry)

	// Test grouping with a non-existent field
	// The groupFn function should skip non-existent fields and continue with valid ones
	err = groupFn(ds, data, []string{"nonexistent", "category"})
	require.NoError(t, err)

	// We should still have 2 entries (grouped by category)
	require.Equal(t, 2, data.Len())
}
