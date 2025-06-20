// Copyright 2024 The Inspektor Gadget authors
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

package filter

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/PaesslerAG/gval"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/constraints"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type comparisonType int

const (
	name            = "filter"
	ParamFilter     = "filter"
	ParamFilterExpr = "filter-expr"
	Priority        = 9000
)

const (
	comparisonTypeUnknown comparisonType = iota
	comparisonTypeMatch
	comparisonTypeRegex
	comparisonTypeLt
	comparisonTypeLte
	comparisonTypeGt
	comparisonTypeGte
)

type filterOperator struct{}

func (f *filterOperator) Name() string {
	return name
}

func (f *filterOperator) Init(params *params.Params) error {
	return nil
}

func (f *filterOperator) GlobalParams() api.Params {
	return nil
}

func (f *filterOperator) InstanceParams() api.Params {
	return api.Params{
		&api.Param{
			Key: ParamFilter,
			Description: `Filter rules
  A filter can match any field using the following syntax:
    field==value     - matches, if the content of field equals exactly value
    field!=value     - matches, if the content of field does not equal exactly value
    field>=value     - matches, if the content of field is greater than or equal to the value
    field>value      - matches, if the content of field is greater than the value
    field<=value     - matches, if the content of field is less than or equal to the value
    field<value      - matches, if the content of field is less than the value
    field~value      - matches, if the content of field matches the regular expression 'value'
    field!~value     - matches, if the content of field does not match the regular expression 'value'
                 see [https://github.com/google/re2/wiki/Syntax] for more information on the syntax
  Multiple filters can be combined using a comma: field1==value1,field2==value2
  It is recommended to use single quotes to escape the filter string, especially if using regular expressions.
  Example: --filter 'field!~regex'
        `,
			Alias: "F",
		},
		&api.Param{
			Key: ParamFilterExpr,
			Description: `Filter rules with an expression language.
  The datasource must be specified as the first part of the expression, followed by a colon, e.g.:
	dsname:field==value
  If there are only one datasource, it can be omitted, but the colon is still required:
    :field==value
                 see [https://github.com/PaesslerAG/gval] for more information on the syntax
`,
			Alias: "E",
		},
	}
}

func (f *filterOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	filterCfg := instanceParamValues[ParamFilter]

	fop := &filterOperatorInstance{
		ffns: map[datasource.DataSource][]func(datasource.DataSource, datasource.Data) bool{},
	}

	filters := api.SplitStringWithEscape(filterCfg, ',')
	for _, filter := range filters {
		if filter == "" {
			continue
		}
		gadgetCtx.Logger().Debugf("adding filter %q", filter)
		err := fop.addFilter(gadgetCtx, filter)
		if err != nil {
			return nil, err
		}
	}

	filterExprCfg := instanceParamValues[ParamFilterExpr]
	if filterExprCfg != "" {
		err := fop.addFilterExpr(gadgetCtx, filterExprCfg)
		if err != nil {
			return nil, err
		}
	}
	return fop, nil
}

func (f *filterOperator) Priority() int {
	return Priority
}

type filterOperatorInstance struct {
	ffns        map[datasource.DataSource][]func(datasource.DataSource, datasource.Data) bool
	filterExprs []func(datasource.DataSource, datasource.Data) bool
}

func (f *filterOperatorInstance) Name() string {
	return name
}

func (f *filterOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, funcs := range f.ffns {
		funcs := funcs
		ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			for _, fn := range funcs {
				if !fn(ds, data) {
					return datasource.ErrDiscard
				}
			}
			return nil
		}, Priority) // TODO: need some predefined & sane values
	}
	return nil
}

func (f *filterOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (f *filterOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func getCompareFunc[T constraints.Ordered](op comparisonType) func(a, b T) bool {
	switch op {
	default:
		return func(a, b T) bool {
			return false
		}
	case comparisonTypeMatch:
		return func(a, b T) bool {
			return a == b
		}
	case comparisonTypeLt:
		return func(a, b T) bool {
			return a < b
		}
	case comparisonTypeGt:
		return func(a, b T) bool {
			return a > b
		}
	case comparisonTypeLte:
		return func(a, b T) bool {
			return a <= b
		}
	case comparisonTypeGte:
		return func(a, b T) bool {
			return a >= b
		}
	}
}

func extractFilter(filter string) (dsName string, fieldName string, op comparisonType, negate bool, value string, err error) {
	// State machine to get filter
	var opString string

	stage := 0
	pos := 0
nextChar:
	for pos < len(filter) {
		switch stage {
		case 0:
			switch filter[pos] {
			case ':':
				dsName = fieldName
				fieldName = ""
				pos++
				continue nextChar
			case '!', '~', '>', '<', '=':
				stage = 1
				continue nextChar
			}
			fieldName += string(filter[pos])
			pos++
		case 1:
			switch filter[pos] {
			case '!', '~', '>', '<', '=':
				opString += string(filter[pos])
				pos++
			default:
				switch opString {
				case "=", "==":
					op = comparisonTypeMatch
				case "!=":
					op = comparisonTypeMatch
					negate = true
				case "<=":
					op = comparisonTypeLte
				case "<":
					op = comparisonTypeLt
				case ">=":
					op = comparisonTypeGte
				case ">":
					op = comparisonTypeGt
				case "~":
					op = comparisonTypeRegex
				case "!~":
					op = comparisonTypeRegex
					negate = true
				default:
					return "", "", comparisonTypeUnknown, false, "",
						fmt.Errorf("invalid operation: %q", opString)
				}
				stage = 2
			}
		case 2:
			value = filter[pos:]
			return
		}
	}
	return "", "", comparisonTypeUnknown, false, "", fmt.Errorf("incomplete filter rule")
}

func (f *filterOperatorInstance) addFilter(gadgetCtx operators.GadgetContext, filter string) error {
	dsName, fieldName, op, negate, value, err := extractFilter(filter)
	if err != nil {
		return fmt.Errorf("extracting filter rule %q: %w", filter, err)
	}

	var filterds datasource.DataSource
	var field datasource.FieldAccessor
	for _, ds := range gadgetCtx.GetDataSources() {
		if dsName != "" && ds.Name() != dsName {
			continue
		}
		nf := ds.GetField(fieldName)
		if nf == nil {
			continue
		}
		if field != nil {
			return fmt.Errorf("ambiguous field name, please specify the datasource")
		}
		field = nf
		filterds = ds
	}

	if field == nil {
		return fmt.Errorf("field %q not found", fieldName)
	}

	ff, err := getFilterFunc(field, op, negate, value)
	if err != nil {
		return err
	}

	f.ffns[filterds] = append(f.ffns[filterds], ff)
	return nil
}

func GetFilterExprFunc(ctx context.Context, ds datasource.DataSource, filter string) (func(ds datasource.DataSource, data datasource.Data) bool, error) {
	extensions := []gval.Language{}
	extensions = append(extensions,
		gval.VariableSelector(func(path gval.Evaluables) gval.Evaluable {
			return func(c context.Context, v interface{}) (interface{}, error) {
				keys, err := path.EvalStrings(c, v)
				if err != nil {
					return nil, err
				}
				accessor := ds.GetField(strings.Join(keys, "."))
				if accessor == nil {
					return nil, err
				}
				data := v.(datasource.Data)
				return accessor.Any(data)
			}
		}),
	)

	var regexpCache sync.Map

	extensions = append(extensions,
		gval.Function("len", func(arguments ...interface{}) (interface{}, error) {
			if len(arguments) != 1 {
				return nil, fmt.Errorf("len function expects exactly one argument, got %d", len(arguments))
			}
			str, ok := arguments[0].(string)
			if !ok {
				return nil, fmt.Errorf("len function expects a string argument, got %T", arguments[0])
			}
			return len(str), nil
		}),
		gval.InfixOperator("matches", func(strI, patternI interface{}) (interface{}, error) {
			str, ok := strI.(string)
			if !ok {
				return nil, fmt.Errorf("expected type string for matches operator but got %T", strI)
			}
			pattern, ok := patternI.(string)
			if !ok {
				return nil, fmt.Errorf("expected type string for matches operator but got %T", patternI)
			}
			var r *regexp.Regexp
			var regexpAny interface{}
			regexpAny, ok = regexpCache.Load(pattern)
			if ok {
				r = regexpAny.(*regexp.Regexp)
			} else {
				var err error
				r, err = regexp.Compile(pattern)
				if err != nil {
					return nil, fmt.Errorf("invalid regular expression: %q", pattern)
				}
				regexpCache.Store(pattern, r)
			}
			matched := r.MatchString(str)
			return matched, nil
		}),
	)
	eval, err := gval.Full(extensions...).
		NewEvaluable(filter)
	if err != nil {
		log.Errorf("parsing filter expression %q: %v", filter, err)
		return nil, err
	}

	return func(ds datasource.DataSource, data datasource.Data) bool {
		b, err := eval.EvalBool(ctx, data)
		if err != nil {
			log.Errorf("evaluating filter expression %q: %v", filter, err)
			return true // if we cannot evaluate the expression, we do not filter out the data
		}
		return b
	}, nil
}

func (f *filterOperatorInstance) addFilterExpr(gadgetCtx operators.GadgetContext, filter string) error {
	datasources := gadgetCtx.GetDataSources()
	filterParts := strings.SplitN(filter, ":", 2)
	var dsPart, filterPart string
	if len(filterParts) != 2 {
		return fmt.Errorf("missing datasource, please specify the datasource")
	}
	dsPart = filterParts[0]
	filterPart = filterParts[1]
	if dsPart == "" && len(datasources) != 1 {
		return fmt.Errorf("ambiguous datasource, please specify the datasource")
	}

	var ds datasource.DataSource
	for name, dsI := range datasources {
		if dsPart == "" || dsPart == name {
			ds = dsI
			dsPart = name
			break
		}
	}
	if ds == nil {
		return fmt.Errorf("datasource %q not found (available datasources: %s)",
			dsPart,
			strings.Join(slices.Collect(maps.Keys(datasources)), ", "))
	}

	ff, err := GetFilterExprFunc(gadgetCtx.Context(), ds, filterPart)
	if err != nil {
		return err
	}
	f.ffns[ds] = append(f.ffns[ds], ff)

	return nil
}

func getFilterFunc(f datasource.FieldAccessor, op comparisonType, negate bool, stringVal string) (
	func(datasource.DataSource, datasource.Data) bool, error,
) {
	var intVal int64
	var uintVal uint64
	var floatVal float64
	var boolVal bool
	var err error

	fieldType := f.Type()

	if (fieldType == api.Kind_String || fieldType == api.Kind_CString) && op == comparisonTypeRegex {
		re, err := regexp.Compile(stringVal)
		if err != nil {
			return nil, fmt.Errorf("invalid regular expression: %q", stringVal)
		}
		return func(ds datasource.DataSource, data datasource.Data) bool {
			val, _ := f.String(data)
			return re.MatchString(val) != negate
		}, nil
	}
	if op == comparisonTypeRegex {
		return nil, fmt.Errorf("regex based filtering can only be used on strings")
	}

	if fieldType == api.Kind_Bool && op != comparisonTypeMatch {
		return nil, fmt.Errorf("boolean values can only be filtered by exact match")
	}

	bitSize := 64
	switch f.Type() {
	case api.Kind_Int8, api.Kind_Uint8:
		bitSize = 8
	case api.Kind_Int16, api.Kind_Uint16:
		bitSize = 16
	case api.Kind_Int32, api.Kind_Uint32, api.Kind_Float32:
		bitSize = 32
	}

	switch f.Type() {
	default:
		return nil, fmt.Errorf("unsupported field type for comparison: %s", f.Type())
	case api.Kind_Int8, api.Kind_Int16, api.Kind_Int32, api.Kind_Int64:
		intVal, err = strconv.ParseInt(stringVal, 10, bitSize)
		if err != nil {
			return nil, fmt.Errorf("parsing comparison value as int: %w", err)
		}
	case api.Kind_Uint8, api.Kind_Uint16, api.Kind_Uint32, api.Kind_Uint64:
		uintVal, err = strconv.ParseUint(stringVal, 10, bitSize)
		if err != nil {
			return nil, fmt.Errorf("parsing comparison value as uint: %w", err)
		}
	case api.Kind_Float32, api.Kind_Float64:
		floatVal, err = strconv.ParseFloat(stringVal, bitSize)
		if err != nil {
			return nil, fmt.Errorf("parsing comparison value as float: %w", err)
		}
	case api.Kind_String, api.Kind_CString, api.Kind_Invalid:
	// Nothing to be done in this case
	case api.Kind_Bool:
		switch stringVal {
		default:
			return nil, fmt.Errorf("parsing comparison value %q as bool", stringVal)
		case "true", "1":
			boolVal = true
		case "false", "0":
		}
	}

	switch f.Type() {
	case api.Kind_String, api.Kind_CString:
		cmp := getCompareFunc[string](op)
		return func(ds datasource.DataSource, data datasource.Data) bool {
			v, _ := f.String(data)
			return cmp(v, stringVal) != negate
		}, nil
	case api.Kind_Int8:
		cmp := getCompareFunc[int8](op)
		val := int8(intVal)
		return func(ds datasource.DataSource, data datasource.Data) bool {
			v, _ := f.Int8(data)
			return cmp(v, val) != negate
		}, nil
	case api.Kind_Int16:
		cmp := getCompareFunc[int16](op)
		val := int16(intVal)
		return func(ds datasource.DataSource, data datasource.Data) bool {
			v, _ := f.Int16(data)
			return cmp(v, val) != negate
		}, nil
	case api.Kind_Int32:
		cmp := getCompareFunc[int32](op)
		val := int32(intVal)
		return func(ds datasource.DataSource, data datasource.Data) bool {
			v, _ := f.Int32(data)
			return cmp(v, val) != negate
		}, nil
	case api.Kind_Int64:
		cmp := getCompareFunc[int64](op)
		val := intVal
		return func(ds datasource.DataSource, data datasource.Data) bool {
			v, _ := f.Int64(data)
			return cmp(v, val) != negate
		}, nil
	case api.Kind_Uint8:
		cmp := getCompareFunc[uint8](op)
		val := uint8(uintVal)
		return func(ds datasource.DataSource, data datasource.Data) bool {
			v, _ := f.Uint8(data)
			return cmp(v, val) != negate
		}, nil
	case api.Kind_Uint16:
		cmp := getCompareFunc[uint16](op)
		val := uint16(uintVal)
		return func(ds datasource.DataSource, data datasource.Data) bool {
			v, _ := f.Uint16(data)
			return cmp(v, val) != negate
		}, nil
	case api.Kind_Uint32:
		cmp := getCompareFunc[uint32](op)
		val := uint32(uintVal)
		return func(ds datasource.DataSource, data datasource.Data) bool {
			v, _ := f.Uint32(data)
			return cmp(v, val) != negate
		}, nil
	case api.Kind_Uint64:
		cmp := getCompareFunc[uint64](op)
		val := uintVal
		return func(ds datasource.DataSource, data datasource.Data) bool {
			v, _ := f.Uint64(data)
			return cmp(v, val) != negate
		}, nil
	case api.Kind_Float32:
		cmp := getCompareFunc[float32](op)
		val := float32(floatVal)
		return func(ds datasource.DataSource, data datasource.Data) bool {
			v, _ := f.Float32(data)
			return cmp(v, val) != negate
		}, nil
	case api.Kind_Float64:
		cmp := getCompareFunc[float64](op)
		val := floatVal
		return func(ds datasource.DataSource, data datasource.Data) bool {
			v, _ := f.Float64(data)
			return cmp(v, val) != negate
		}, nil
	case api.Kind_Bool:
		if op != comparisonTypeMatch {
			return nil, fmt.Errorf("invalid comparison value for bool field %s", f.Name())
		}
		return func(ds datasource.DataSource, data datasource.Data) bool {
			v, _ := f.Bool(data)
			return (v == boolVal) != negate
		}, nil
	}

	return nil, fmt.Errorf("unsupported type: %s", f.Type())
}

func init() {
	operators.RegisterDataOperator(&filterOperator{})
}

var FilterOperator = &filterOperator{}
