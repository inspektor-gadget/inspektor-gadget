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
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	Name       = "group"
	ParamGroup = "group"
	Priority   = 9400

	// Annotation keys
	AnnotationAggregation = "group.aggregation"
	AnnotationSeparator   = "group.separator"

	// Aggregation methods
	AggregationSum    = "sum"
	AggregationMin    = "min"
	AggregationMax    = "max"
	AggregationAvg    = "avg"
	AggregationFirst  = "first"
	AggregationLast   = "last"
	AggregationConcat = "concat"
)

type groupOperator struct{}

func (g *groupOperator) Name() string {
	return Name
}

func (g *groupOperator) Init(params *params.Params) error {
	return nil
}

func (g *groupOperator) GlobalParams() api.Params {
	return nil
}

func (g *groupOperator) InstanceParams() api.Params {
	return api.Params{
		{
			Key:   ParamGroup,
			Title: "Group By Fields",
			Description: "Comma-separated list of field names to group by. " +
				"For multiple datasources, prefix the field Name with 'datasourcename:'. " +
				"Example: field1,field2 or datasource1:field1,datasource2:field2",
			DefaultValue: "",
			TypeHint:     api.TypeString,
		},
	}
}

func (g *groupOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	// Check if there are array datasources
	found := false
	for _, ds := range gadgetCtx.GetDataSources() {
		if ds.Type() == datasource.TypeArray {
			found = true
			break
		}
	}
	if !found {
		gadgetCtx.Logger().Debug("group: no array data sources found. Don't instantiate")
		return nil, nil
	}

	// Get the group parameter
	groupParam, ok := instanceParamValues[ParamGroup]
	if !ok {
		return nil, fmt.Errorf("missing %s", ParamGroup)
	}

	// Parse the group parameter
	groupFields, err := apihelpers.GetStringValuesPerDataSource(groupParam)
	if err != nil {
		return nil, fmt.Errorf("parsing %s (%q): %w", ParamGroup, groupParam, err)
	}
	if len(groupFields) == 0 {
		return nil, fmt.Errorf("invalid value for %s: %s", ParamGroup, groupParam)
	}

	return &groupOperatorInstance{
		groupFields: groupFields,
	}, nil
}

func (g *groupOperator) Priority() int {
	return Priority
}

type groupOperatorInstance struct {
	groupFields map[string]string
}

// Ensure groupOperatorInstance implements operators.PreStart
var _ operators.PreStart = (*groupOperatorInstance)(nil)

func (g *groupOperatorInstance) Name() string {
	return Name
}

func (g *groupOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for _, ds := range gadgetCtx.GetDataSources() {
		if ds.Type() != datasource.TypeArray {
			continue
		}

		var groupFieldsStr string
		if val, ok := g.groupFields[""]; ok {
			// Global fields specified
			groupFieldsStr = val
		} else if val, ok := g.groupFields[ds.Name()]; ok {
			// Datasource-specific fields specified
			groupFieldsStr = val
		} else {
			// No fields specified for this datasource
			continue
		}

		// Split the comma-separated field names
		fieldsToGroupBy := strings.Split(groupFieldsStr, ",")

		// Validate that all fields exist
		for _, fieldName := range fieldsToGroupBy {
			fieldName = strings.TrimSpace(fieldName)
			if fieldName == "" {
				continue
			}
			if ds.GetField(fieldName) == nil {
				return fmt.Errorf("field %q not found in data source %q", fieldName, ds.Name())
			}
		}

		gadgetCtx.Logger().Debugf("group: data source %q grouping by fields %v", ds.Name(), fieldsToGroupBy)

		ds.SubscribeArray(func(ds datasource.DataSource, data datasource.DataArray) error {
			return groupFn(ds, data, fieldsToGroupBy)
		}, Priority)
	}
	return nil
}

func (g *groupOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (g *groupOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

// groupFn groups the data by the specified fields and aggregates the remaining fields
func groupFn(ds datasource.DataSource, data datasource.DataArray, groupByFields []string) error {
	if data.Len() == 0 {
		return nil
	}

	// Create a map to store grouped data
	// The key is a string representation of the group by fields values
	// The value is the index of the first entry in that group
	groups := make(map[string]int)

	// Create a map to track the count of entries in each group (for avg calculation)
	groupCounts := make(map[string]int)

	// Get all fields from the datasource
	allFields := ds.Accessors(false)

	// First pass: identify groups and initialize aggregation
	for i := 0; i < data.Len(); i++ {
		entry := data.Get(i)

		// Create a key for this entry based on the group by fields
		var keyParts []string
		for _, fieldName := range groupByFields {
			field := ds.GetField(fieldName)
			if field == nil {
				continue
			}

			// Get the field value as string for the key
			var fieldValue string
			strVal, err := field.String(entry)
			if err == nil {
				fieldValue = strVal
			} else {
				// Try other types
				if intVal, err := field.Int64(entry); err == nil {
					fieldValue = fmt.Sprintf("%d", intVal)
				} else if uintVal, err := field.Uint64(entry); err == nil {
					fieldValue = fmt.Sprintf("%d", uintVal)
				} else if floatVal, err := field.Float64(entry); err == nil {
					fieldValue = fmt.Sprintf("%f", floatVal)
				} else if boolVal, err := field.Bool(entry); err == nil {
					fieldValue = fmt.Sprintf("%t", boolVal)
				} else {
					// Use empty string if we can't convert
					fieldValue = ""
				}
			}

			keyParts = append(keyParts, fieldValue)
		}

		groupKey := strings.Join(keyParts, ":")

		if idx, exists := groups[groupKey]; exists {
			// Group already exists, aggregate values
			groupCounts[groupKey]++

			// Get the representative entry for this group
			repEntry := data.Get(idx)

			// Aggregate fields that are not in the group by list
			for _, field := range allFields {
				// Skip group by fields
				isGroupByField := false
				for _, groupField := range groupByFields {
					if field.Name() == groupField {
						isGroupByField = true
						break
					}
				}
				if isGroupByField {
					continue
				}

				// Get aggregation method from annotation
				aggregation := AggregationFirst // default for non-numeric
				if annotations := field.Annotations(); annotations != nil {
					if aggMethod, ok := annotations[AnnotationAggregation]; ok {
						aggregation = aggMethod
					}
				}

				// For numeric fields, default to sum
				isNumeric := false
				var numericValue float64

				// Try to get numeric value
				if intVal, err := field.Int64(entry); err == nil {
					numericValue = float64(intVal)
					isNumeric = true
				} else if uintVal, err := field.Uint64(entry); err == nil {
					numericValue = float64(uintVal)
					isNumeric = true
				} else if floatVal, err := field.Float64(entry); err == nil {
					numericValue = floatVal
					isNumeric = true
				}

				if isNumeric {
					// Default aggregation for numeric values is sum
					if aggregation == "" {
						aggregation = AggregationSum
					}

					// Get current value from representative entry
					var currentValue float64
					if intVal, err := field.Int64(repEntry); err == nil {
						currentValue = float64(intVal)
					} else if uintVal, err := field.Uint64(repEntry); err == nil {
						currentValue = float64(uintVal)
					} else if floatVal, err := field.Float64(repEntry); err == nil {
						currentValue = floatVal
					}

					// Perform aggregation
					var newValue float64
					switch aggregation {
					case AggregationSum:
						newValue = currentValue + numericValue
					case AggregationMin:
						if numericValue < currentValue {
							newValue = numericValue
						} else {
							newValue = currentValue
						}
					case AggregationMax:
						if numericValue > currentValue {
							newValue = numericValue
						} else {
							newValue = currentValue
						}
					case AggregationAvg:
						// We'll calculate the average in the second pass
						newValue = currentValue + numericValue
					case AggregationFirst:
						newValue = currentValue
					case AggregationLast:
						newValue = numericValue
					default:
						newValue = currentValue
					}

					// Update the field value
					if _, err := field.Int64(repEntry); err == nil {
						field.PutInt64(repEntry, int64(newValue))
					} else if _, err := field.Uint64(repEntry); err == nil {
						field.PutUint64(repEntry, uint64(newValue))
					} else if _, err := field.Float64(repEntry); err == nil {
						field.PutFloat64(repEntry, newValue)
					}
				} else {
					// Handle string fields
					if strVal, err := field.String(entry); err == nil {
						currentStr, _ := field.String(repEntry)

						// Default aggregation for strings is first
						if aggregation == "" {
							aggregation = AggregationFirst
						}

						var newStr string
						switch aggregation {
						case AggregationFirst:
							newStr = currentStr
						case AggregationLast:
							newStr = strVal
						case AggregationConcat:
							separator := " "
							if annotations := field.Annotations(); annotations != nil {
								if sep, ok := annotations[AnnotationSeparator]; ok {
									separator = sep
								}
							}
							if currentStr == "" {
								newStr = strVal
							} else {
								newStr = currentStr + separator + strVal
							}
						default:
							newStr = currentStr
						}

						field.PutString(repEntry, newStr)
					}
				}
			}
		} else {
			// New group, store the index
			groups[groupKey] = i
			groupCounts[groupKey] = 1

			// For numeric fields, set the default aggregation method to "sum"
			// This ensures that the first entry in each group is properly initialized
			for _, field := range allFields {
				// Skip group by fields
				isGroupByField := false
				for _, groupField := range groupByFields {
					if field.Name() == groupField {
						isGroupByField = true
						break
					}
				}
				if isGroupByField {
					continue
				}

				// Check if this is a numeric field
				entry := data.Get(i)
				isNumeric := false
				if _, err := field.Int64(entry); err == nil {
					isNumeric = true
				} else if _, err := field.Uint64(entry); err == nil {
					isNumeric = true
				} else if _, err := field.Float64(entry); err == nil {
					isNumeric = true
				}

				if isNumeric {
					// Set default aggregation for numeric fields
					if annotations := field.Annotations(); annotations == nil || annotations[AnnotationAggregation] == "" {
						field.AddAnnotation(AnnotationAggregation, AggregationSum)
					}
				}
			}
		}
	}

	// Second pass: finalize aggregation (e.g., calculate averages)
	for groupKey, idx := range groups {
		repEntry := data.Get(idx)
		count := groupCounts[groupKey]

		for _, field := range allFields {
			// Skip group by fields
			isGroupByField := false
			for _, groupField := range groupByFields {
				if field.Name() == groupField {
					isGroupByField = true
					break
				}
			}
			if isGroupByField {
				continue
			}

			// Check if this field uses avg aggregation
			aggregation := ""
			if annotations := field.Annotations(); annotations != nil {
				if aggMethod, ok := annotations[AnnotationAggregation]; ok {
					aggregation = aggMethod
				}
			}

			if aggregation == AggregationAvg {
				// Calculate average
				if intVal, err := field.Int64(repEntry); err == nil {
					field.PutInt64(repEntry, intVal/int64(count))
				} else if uintVal, err := field.Uint64(repEntry); err == nil {
					field.PutUint64(repEntry, uintVal/uint64(count))
				} else if floatVal, err := field.Float64(repEntry); err == nil {
					field.PutFloat64(repEntry, floatVal/float64(count))
				}
			}
		}
	}

	// Create a new array with only the grouped entries
	newLen := len(groups)
	if newLen == 0 {
		return nil
	}

	// Create a slice to store the indices of the representative entries
	indices := make([]int, 0, newLen)
	for _, idx := range groups {
		indices = append(indices, idx)
	}

	// Sort the indices to maintain a consistent order
	for i := 0; i < len(indices); i++ {
		for j := i + 1; j < len(indices); j++ {
			if indices[j] < indices[i] {
				indices[i], indices[j] = indices[j], indices[i]
			}
		}
	}

	// Move the representative entries to the beginning of the array
	for i, idx := range indices {
		if i != idx {
			data.Swap(i, idx)
		}
	}

	// Resize the array to contain only the grouped entries
	if err := data.Resize(newLen); err != nil {
		return fmt.Errorf("resizing data array to %d entries: %w", newLen, err)
	}

	return nil
}

var Operator = &groupOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}
