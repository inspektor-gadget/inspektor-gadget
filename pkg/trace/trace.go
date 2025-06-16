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
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
)

func RegisterGlobalProvider(ctx context.Context) (func(context.Context) error, error) {
	expType := config.Config.GetString("otel.trace.exporter")

	var funcs []func(context.Context) error

	sf := func(ctx context.Context) error {
		for _, fn := range funcs {
			fn(ctx)
		}
		return nil
	}

	if expType == "" {
		// not enabled
		return sf, nil
	}

	var err error
	var exp sdktrace.SpanExporter

	switch expType {
	case "file":
		filename := config.Config.GetString("otel.trace.filename")
		if filename == "" {
			return sf, fmt.Errorf("otel.trace.filename not set")
		}

		f, err := os.Create(filename)
		if err != nil {
			return sf, fmt.Errorf("creating otel.trace.filename: %w", err)
		}
		funcs = append(funcs, func(ctx context.Context) error {
			return f.Close()
		})

		exp, err = stdouttrace.New(
			stdouttrace.WithPrettyPrint(),
			stdouttrace.WithWriter(f),
		)
		if err != nil {
			return nil, fmt.Errorf("creating stdout exporter: %w", err)
		}
	case "otlp-grpc":
		endpoint := config.Config.GetString("otel.trace.endpoint")
		insecure := config.Config.GetBool("otel.trace.insecure")

		var options []otlptracegrpc.Option
		if insecure {
			options = append(options, otlptracegrpc.WithInsecure())
		}
		options = append(options, otlptracegrpc.WithEndpoint(endpoint))
		client := otlptracegrpc.NewClient(options...)
		exp, err = otlptrace.New(ctx, client)
		if err != nil {
			return sf, err
		}
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("inspektor-gadget"),
			semconv.ServiceVersionKey.String(version.Version().String()),
		),
	)
	if err != nil {
		return sf, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()), // or parent-based, etc.
		sdktrace.WithResource(res),
	)

	// Register as global
	otel.SetTracerProvider(tp)

	funcs = append([]func(context.Context) error{tp.Shutdown}, funcs...)

	log.Infof("initialized tracing")
	return sf, nil
}
