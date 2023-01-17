// Copyright 2022-2023 The Inspektor Gadget authors
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

package containercollection

import (
	"errors"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func (cc *ContainerCollection) Enrich(next func(any) error) func(any) error {
	return func(ev any) error {
		err := cc.EnrichEvent(ev)
		if err != nil {
			return err
		}
		return next(ev)
	}
}

func (cc *ContainerCollection) EnrichEvent(ev any) error {
	event, ok := ev.(operators.ContainerInfoFromMountNSID)
	if !ok {
		return errors.New("invalid event to enrich")
	}
	event.SetNode(cc.nodeName)

	container := cc.LookupContainerByMntns(event.GetMountNSID())
	if container != nil {
		event.SetContainerInfo(container.Podname, container.Namespace, container.Name)
	}
	return nil
}
