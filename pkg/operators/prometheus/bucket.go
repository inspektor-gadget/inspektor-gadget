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

package prometheus

import (
	"math"
	"strings"

	"github.com/shopspring/decimal"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/prometheus/config"
)

type BucketType string

const (
	BucketTypeExp2   BucketType = "exp2"
	BucketTypeLinear BucketType = "linear"
)

var AllBucketTypes = map[string]struct{}{
	string(BucketTypeExp2):   {},
	string(BucketTypeLinear): {},
}

type BucketConfig struct {
	Type       BucketType
	Min        int
	Max        int
	Multiplier float64
}

func bucketConfigsFromConfig(c *config.Config) map[string]*BucketConfig {
	if c == nil {
		return nil
	}
	buckets := make(map[string]*BucketConfig)
	for _, m := range c.Metrics {
		if strings.ToLower(m.Type) == "histogram" {
			buckets[m.Name] = &BucketConfig{
				Type:       BucketType(m.Bucket.Type),
				Min:        m.Bucket.Min,
				Max:        m.Bucket.Max,
				Multiplier: m.Bucket.Multiplier,
			}
		}
	}
	return buckets
}

func (c *BucketConfig) buckets() []float64 {
	switch c.Type {
	case BucketTypeExp2:
		return exp2Buckets(c.Min, c.Max, c.Multiplier)
	case BucketTypeLinear:
		return linearBuckets(c.Min, c.Max, c.Multiplier)
	default:
		log.Warnf("unknown bucket type: %s", c.Type)
		return nil
	}
}

func exp2Buckets(min, max int, multiplier float64) []float64 {
	buckets := make([]float64, 0, max-min)
	for i := min; i < max; i++ {
		buckets = append(buckets, math.Pow(2, float64(i))*multiplier)
	}
	return buckets
}

func linearBuckets(min, max int, multiplier float64) []float64 {
	buckets := make([]float64, 0, max-min)
	for i := min; i < max; i++ {
		bucketId := decimal.NewFromInt(int64(i))
		bucketValue, _ := bucketId.Mul(decimal.NewFromFloat(multiplier)).Float64()
		buckets = append(buckets, bucketValue)
	}
	return buckets
}
