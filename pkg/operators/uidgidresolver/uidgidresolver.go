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

// Package uidgidresolver provides an operator that enriches events by looking
// up uid and gid resolving them to the corresponding username and groupname.
// Only /etc/passwd and /etc/group is read on the host. Therefore the name for a
// corresponding id could be wrong.
package uidgidresolver

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/annotations"
)

const (
	OperatorName          = "UidGidResolver"
	DefaultUserFieldName  = "user"
	DefaultGroupFieldName = "group"
)

type UidResolverInterface interface {
	GetUid() uint32
	SetUserName(string)
}

type GidResolverInterface interface {
	GetGid() uint32
	SetGroupName(string)
}

type UidGidResolver struct{}

func (k *UidGidResolver) Name() string {
	return OperatorName
}

func (k *UidGidResolver) Description() string {
	return "UidGidResolver resolves uid and gid to username and groupname"
}

func (k *UidGidResolver) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (k *UidGidResolver) GlobalParams() api.Params {
	return nil
}

func (k *UidGidResolver) InstanceParams() api.Params {
	return nil
}

func (k *UidGidResolver) ParamDescs() params.ParamDescs {
	return nil
}

func (k *UidGidResolver) Dependencies() []string {
	return nil
}

func (k *UidGidResolver) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	_, hasUidResolverInterface := gadget.EventPrototype().(UidResolverInterface)
	_, hasGidResolverInterface := gadget.EventPrototype().(GidResolverInterface)
	return hasUidResolverInterface || hasGidResolverInterface
}

func (k *UidGidResolver) Init(params *params.Params) error {
	return nil
}

func (k *UidGidResolver) Close() error {
	return nil
}

func (k *UidGidResolver) Priority() int {
	return 5
}

func (k *UidGidResolver) Instantiate(gadgetCtx operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	uidGidCache := GetUserGroupCache()

	return &UidGidResolverInstance{
		gadgetCtx:      gadgetCtx,
		gadgetInstance: gadgetInstance,
		uidGidCache:    uidGidCache,
	}, nil
}

type fieldAccPair struct {
	srcFieldAcc datasource.FieldAccessor
	dstFieldAcc datasource.FieldAccessor
}

func (k *UidGidResolver) InstantiateDataOperator(gadgetCtx operators.GadgetContext, paramValues api.ParamValues) (operators.DataOperatorInstance, error) {
	logger := gadgetCtx.Logger()
	fieldsUid := make(map[datasource.DataSource][]fieldAccPair)
	fieldsGid := make(map[datasource.DataSource][]fieldAccPair)
	// Find things we can enrich
	for _, ds := range gadgetCtx.GetDataSources() {
		logger.Debugf("UidGidResolver inspecting datasource %q", ds.Name())

		uids := ds.GetFieldsWithTag("type:" + ebpftypes.UidTypeName)
		gids := ds.GetFieldsWithTag("type:" + ebpftypes.GidTypeName)

		if len(uids) > 0 {
			logger.Debugf("> found %d uid fields", len(uids))

			for _, uid := range uids {
				outName, err := annotations.GetTargetNameFromAnnotation(logger, "uidgidresolver.uid", uid, "uidgidresolver.target")
				if err != nil {
					logger.Debugf("no target name found for uid, falling back to %s", DefaultUserFieldName)
					outName = DefaultUserFieldName
				}
				uidStrField, err := ds.AddField(outName, api.Kind_String, datasource.WithSameParentAs(uid))
				if err != nil {
					return nil, err
				}
				uidStrField.SetHidden(true, false)

				uid.SetHidden(true, false)
				fieldsUid[ds] = append(fieldsUid[ds], fieldAccPair{srcFieldAcc: uid, dstFieldAcc: uidStrField})
			}
		}

		if len(gids) > 0 {
			logger.Debugf("> found %d gid fields", len(gids))

			for _, gid := range gids {
				outName, err := annotations.GetTargetNameFromAnnotation(logger, "uidgidresolver.gid", gid, "uidgidresolver.target")
				if err != nil {
					logger.Debugf("no target name found for gid, falling back to %s", DefaultGroupFieldName)
					outName = DefaultGroupFieldName
				}
				gidStrField, err := ds.AddField(outName, api.Kind_String, datasource.WithSameParentAs(gid))
				if err != nil {
					return nil, err
				}
				gidStrField.SetHidden(true, false)

				gid.SetHidden(true, false)
				fieldsGid[ds] = append(fieldsGid[ds], fieldAccPair{srcFieldAcc: gid, dstFieldAcc: gidStrField})
			}
		}
	}

	if len(fieldsUid) == 0 && len(fieldsGid) == 0 {
		return nil, nil
	}

	return &UidGidResolverInstance{
		uidGidCache: GetUserGroupCache(),
		fieldsUid:   fieldsUid,
		fieldsGid:   fieldsGid,
	}, nil
}

type UidGidResolverInstance struct {
	gadgetCtx      operators.GadgetContext
	gadgetInstance any
	uidGidCache    UserGroupCache
	fieldsUid      map[datasource.DataSource][]fieldAccPair
	fieldsGid      map[datasource.DataSource][]fieldAccPair
}

func (m *UidGidResolverInstance) Name() string {
	return "UidGidResolverInstance"
}

func (m *UidGidResolverInstance) PreGadgetRun() error {
	return m.uidGidCache.Start()
}

func (m *UidGidResolverInstance) PostGadgetRun() error {
	m.uidGidCache.Stop()
	return nil
}

func (m *UidGidResolverInstance) enrich(ev any) {
	uidResolver := ev.(UidResolverInterface)
	if uidResolver != nil {
		uid := uidResolver.GetUid()
		uidResolver.SetUserName(m.uidGidCache.GetUsername(uid))
	}

	gidResolver := ev.(GidResolverInterface)
	if gidResolver != nil {
		gid := gidResolver.GetGid()
		gidResolver.SetGroupName(m.uidGidCache.GetGroupname(gid))
	}
}

func (m *UidGidResolverInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, fieldAccPairs := range m.fieldsUid {
		for _, fieldAccPair := range fieldAccPairs {
			ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
				uid, err := fieldAccPair.srcFieldAcc.Uint32(data)
				if err != nil {
					return err
				}
				username := m.uidGidCache.GetUsername(uid)
				if username == "" {
					username = fmt.Sprintf("uid:%d", uid)
				}
				fieldAccPair.dstFieldAcc.PutString(data, username)
				return nil
			}, 0)
		}
	}

	for ds, fieldAccPairs := range m.fieldsGid {
		for _, fieldAccPair := range fieldAccPairs {
			ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
				gid, err := fieldAccPair.srcFieldAcc.Uint32(data)
				if err != nil {
					return err
				}
				groupname := m.uidGidCache.GetGroupname(gid)
				if groupname == "" {
					groupname = fmt.Sprintf("gid:%d", gid)
				}
				fieldAccPair.dstFieldAcc.PutString(data, groupname)
				return nil
			}, 1)
		}
	}

	// We need to start the cache here because it's too late to start it in
	// Start() as other operators could be started before and generate events
	// that need the cache
	if err := m.uidGidCache.Start(); err != nil {
		return err
	}

	return nil
}

func (m *UidGidResolverInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (m *UidGidResolverInstance) Stop(gadgetCtx operators.GadgetContext) error {
	m.uidGidCache.Stop()
	return nil
}

func (m *UidGidResolverInstance) Close(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (m *UidGidResolverInstance) EnrichEvent(ev any) error {
	m.enrich(ev)
	return nil
}

func init() {
	operators.Register(&UidGidResolver{})
	operators.RegisterDataOperator(&UidGidResolver{})
}
