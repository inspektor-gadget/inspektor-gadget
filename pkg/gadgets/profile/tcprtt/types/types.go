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

package types

import (
	histogram "github.com/inspektor-gadget/inspektor-gadget/pkg/histogram"
)

type AddressType string

const (
	AddressTypeLocal  AddressType = "Local"
	AddressTypeRemote AddressType = "Remote"
	AddressTypeAll    AddressType = "All Addresses"

	WildcardAddress = "******"
)

// ExtendedHistogram extends the histogram.Histogram type with the address and
// address type for which the histogram was created. In addition, it adds the
// average value of the histogram.
type ExtendedHistogram struct {
	// Histogram is the Histogram of the RTT values.
	*histogram.Histogram `json:",inline"`

	// Address is the address for which the histogram was created. It is
	// AllAddresses for a global histogram.
	Address string `json:"address,omitempty"`

	// AddressType is the type of the address for which the histogram was
	// created. It is AddressTypeAll for a global histogram.
	AddressType AddressType `json:"addressType,omitempty"`

	// Average is the average value of the histogram.
	Average float64 `json:"average,omitempty"`
}

type Report struct {
	Histograms []*ExtendedHistogram `json:"histograms,omitempty"`
}

func NewHistogram(
	unit histogram.Unit,
	slots []uint32,
	addressType AddressType,
	addr string,
	avg float64,
) *ExtendedHistogram {
	return &ExtendedHistogram{
		Histogram: &histogram.Histogram{
			Unit:      unit,
			Intervals: histogram.NewIntervalsFromExp2Slots(slots),
		},
		AddressType: addressType,
		Address:     addr,
		Average:     avg,
	}
}
