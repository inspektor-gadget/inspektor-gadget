// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package annotations

import (
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

func GetTargetNameFromAnnotation(
	logger logger.Logger,
	logPrefix string,
	in datasource.FieldAccessor,
	targetAnnotation string,
) (string, error) {
	annotations := in.Annotations()

	if outName, ok := annotations[targetAnnotation]; ok {
		logger.Debugf("%s: using custom target field %q for field %q", logPrefix, outName, in.Name())
		return outName, nil
	}

	if outName, ok := strings.CutSuffix(in.Name(), "_raw"); ok {
		logger.Debugf("%s: using %q as target field for %q", logPrefix, outName, in.Name())
		return outName, nil
	}

	return "", fmt.Errorf("neither %q annotation nor '_raw' suffix found", targetAnnotation)
}
