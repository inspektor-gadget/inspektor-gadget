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

// Package systemdresolver provides an operator that enriches events by
// resolving cgroupids to systemd unit names
package systemdresolver

import (
	"fmt"
	"path"
	"sync"

	cgrouphook "github.com/inspektor-gadget/inspektor-gadget/pkg/cgroup-hook"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	OperatorName         = "SystemdResolver"
	OperatorInstanceName = "SystemdResolverInstance"
)

type SystemdResolverInterface interface {
	GetCgroupID() uint64
	SetSystemdName(name string)
}

type SystemdResolver struct {
	cgroupNotifier *cgrouphook.CgroupNotifier
	idToUnitname   sync.Map // map[cgroupID]unitname
	subCount       int
	subCountMutex  sync.Mutex
}

func (k *SystemdResolver) Name() string {
	return OperatorName
}

func (k *SystemdResolver) Description() string {
	return "SystemdResolver resolves cgroup ids to systemd unit names"
}

func (k *SystemdResolver) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (k *SystemdResolver) ParamDescs() params.ParamDescs {
	return nil
}

func (k *SystemdResolver) Dependencies() []string {
	return nil
}

func (k *SystemdResolver) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	_, hasSystemdResolverInterface := gadget.EventPrototype().(SystemdResolverInterface)
	return hasSystemdResolverInterface
}

func (k *SystemdResolver) Init(params *params.Params) error {
	cgroupNotifier, err := cgrouphook.GetCgroupNotifier()
	if err != nil {
		return fmt.Errorf("getting cgroup notifier: %w", err)
	}
	k.cgroupNotifier = cgroupNotifier
	return nil
}

func (k *SystemdResolver) Close() error {
	return nil
}

func (k *SystemdResolver) AddCgroup(cgroupPath string, id uint64) {
	unitName := path.Base(cgroupPath)
	k.idToUnitname.Store(id, unitName)
}

func (k *SystemdResolver) RemoveCgroup(cgroupPath string, id uint64) {
	k.idToUnitname.Delete(id)
}

func (k *SystemdResolver) Instantiate(gadgetCtx operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	enableSystemdParam := params.Get(localmanager.Systemd)
	if enableSystemdParam != nil && !enableSystemdParam.AsBool() {
		return nil, nil
	}
	return &SystemdResolverInstance{
		gadgetCtx:      gadgetCtx,
		manager:        k,
		gadgetInstance: gadgetInstance,
	}, nil
}

type SystemdResolverInstance struct {
	gadgetCtx      operators.GadgetContext
	manager        *SystemdResolver
	gadgetInstance any
}

func (m *SystemdResolverInstance) Name() string {
	return OperatorInstanceName
}

func (m *SystemdResolverInstance) PreGadgetRun() error {
	m.manager.subCountMutex.Lock()
	defer m.manager.subCountMutex.Unlock()
	m.manager.subCount++
	if m.manager.subCount == 1 {
		m.manager.idToUnitname = sync.Map{}
		m.manager.cgroupNotifier.Subscribe(m.manager, true)
	}
	m.manager.cgroupNotifier.Start()
	return nil
}

func (m *SystemdResolverInstance) PostGadgetRun() error {
	m.manager.subCountMutex.Lock()
	defer m.manager.subCountMutex.Unlock()
	m.manager.subCount--
	if m.manager.subCount == 0 {
		m.manager.cgroupNotifier.Unsubscribe(m.manager)
	}
	m.manager.cgroupNotifier.Stop()
	return nil
}

func (m *SystemdResolverInstance) enrich(ev any) {
	cgroupId := ev.(SystemdResolverInterface).GetCgroupID()
	name, ok := m.manager.idToUnitname.Load(cgroupId)
	if ok {
		ev.(SystemdResolverInterface).SetSystemdName(name.(string))
	}
}

func (m *SystemdResolverInstance) EnrichEvent(ev any) error {
	m.enrich(ev)
	return nil
}

func init() {
	operators.Register(&SystemdResolver{})
}
