// Package telem provides functionality for initializing and managing
// telemetry, including metrics and tracing, using OpenTelemetry and Prometheus.
//
// InitMetrics initializes a Prometheus metrics exporter and starts an HTTP
// server to serve the metrics at the /metrics endpoint. It returns a function
// to shut down the metrics server and the meter provider.
//
// Parameters:
// - service: The name of the service for which metrics are being collected.
//
// Returns:
// - ShutdownMetrics: A function to shut down the metrics server and meter provider.
// - error: An error if initialization fails.
//
// InitTracing initializes tracing with an OTLP exporter and sets up a tracer
// provider. It returns a function to shut down the tracer provider.
//
// Parameters:
// - service: The name of the service for which tracing is being collected.
//
// Returns:
// - ShutdownTracing: A function to shut down the tracer provider.
// - error: An error if initialization fails.
package telem

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	_ "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	_ "go.opentelemetry.io/otel/trace"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ShutdownMetrics func(ctx context.Context) error

// InitMetrics initializes Prometheus metrics exporter
func InitMetrics(service string) (ShutdownMetrics, error) {
	res, err := resource.New(context.Background(),
		resource.WithSchemaURL(semconv.SchemaURL),
		resource.WithAttributes(semconv.ServiceNameKey.String(service)),
	)
	if err != nil {
		return nil, err
	}

	exporter, err := prometheus.New()
	if err != nil {
		return nil, err
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithReader(exporter),
		metric.WithResource(res),
	)
	otel.SetMeterProvider(meterProvider)

	// FIX: the address was hard-coded; METRICS_ADDR now overrides the default :9000.
	addr := os.Getenv("METRICS_ADDR")
	if addr == "" {
		addr = ":9000"
	}
	srv := &http.Server{Addr: addr, Handler: promhttp.Handler()}
	go func() {
		log.Printf("Prometheus metrics server running at %s/metrics", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start Prometheus metrics server: %v", err)
		}
	}()

	return func(ctx context.Context) error {
		if err := srv.Shutdown(ctx); err != nil {
			return err
		}
		return meterProvider.Shutdown(ctx)
	}, nil
}

type ShutdownTracing func(ctx context.Context) error

// InitTracing initializes tracing with OTLP exporter
func InitTracing(service string) (ShutdownTracing, error) {
	exporter, err := otlptrace.New(
		context.Background(),
		// FIX: the endpoint was "localhost:8000", which is this API's own port, so spans
		// were POSTed to /v1/traces on our own router and dropped. With no WithEndpoint,
		// the exporter uses the OTLP/HTTP default (localhost:4318) or the
		// OTEL_EXPORTER_OTLP_ENDPOINT env var if set.
		otlptracehttp.NewClient(
			otlptracehttp.WithInsecure(),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
	}

	res, err := resource.New(
		context.Background(),
		resource.WithAttributes(semconv.ServiceNameKey.String(service)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	tp := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}
