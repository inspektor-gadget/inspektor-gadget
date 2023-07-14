// Copyright 2023 The Inspektor Gadget authors
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

package textcolumns

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func (tf *TextColumnsFormatter[T]) Params() params.Params {
	pd := make(params.Params, 0)
	for _, col := range tf.columns {
		if col.col.Category == "" {
			continue
		}
		_, ok := tf.categories[col.col.Category]
		if ok {
			continue
		}
		visbility := tf.options.CategoryDefault
		if tf.options.CategoryDefaults != nil {
			if v, ok := tf.options.CategoryDefaults[col.col.Category]; ok {
				visbility = v
			}
		}
		defaultValue := "false"
		if visbility {
			defaultValue = "true"
		}

		param := (&params.ParamDesc{
			Key:          col.col.Category,
			DefaultValue: defaultValue,
			Description:  fmt.Sprintf("display %s fields", col.col.Category),
			TypeHint:     params.TypeBool,
		}).ToParam()
		tf.categories[col.col.Category] = param
		pd.Add(param)
	}
	return pd
}
