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

package trace

import (
	"context"

	"github.com/spf13/viper"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
)

func RegisterGlobalProvider(ctx context.Context) error {
	endpoint := viper.GetString("otel.trace.endpoint")
	insecure := viper.GetBool("otel.trace.insecure")

	if endpoint == "" {
		// not enabled
		return nil
	}

	var options []otlptracegrpc.Option

	if insecure {
		options = append(options, otlptracegrpc.WithInsecure())
	}
	options = append(options, otlptracegrpc.WithEndpoint(endpoint))

	client := otlptracegrpc.NewClient(options...)
	exp, err := otlptrace.New(ctx, client)
	if err != nil {
		return err
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("inspektor-gadget"),
			semconv.ServiceVersionKey.String(version.Version().String()),
		),
	)
	if err != nil {
		return err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()), // or parent-based, etc.
		sdktrace.WithResource(res),
	)

	// Register as global
	otel.SetTracerProvider(tp)
	return nil
}
