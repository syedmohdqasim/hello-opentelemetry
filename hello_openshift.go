// Copyright The OpenTelemetry Authors
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

// Example using OTLP exporters + collector + third-party backends. For
// information about using the exporter, see:
// https://pkg.go.dev/go.opentelemetry.io/otel/exporters/otlp?tab=doc#example-package-Insecure
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type loggerKeyType int

const loggerKey loggerKeyType = iota

var logger *zap.Logger

func newContext(ctx context.Context, fields ...zap.Field) context.Context {
	return context.WithValue(ctx, loggerKey, logWithContext(ctx))
}

func logWithContext(ctx context.Context) *zap.Logger {
	logger, _ = zap.NewProduction()
	if ctx == nil {
		return logger
	}
	if ctxLogger, ok := ctx.Value(loggerKey).(zap.Logger); ok {
		return &ctxLogger
	} else {
		return logger
	}
}

// Initializes an OTLP exporter, and configures the corresponding trace and
// metric providers.
func initProvider() (oteltrace.TracerProvider, func(context.Context) error, error) {
	ctx := context.Background()

	res, err := resource.New(ctx,
		resource.WithAttributes(
			// the service name used to display traces in backends
			semconv.ServiceNameKey.String("test-service"),
		),
	)
	if err != nil {
		return oteltrace.NewNoopTracerProvider(), nil, fmt.Errorf("failed to create resource: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "otelcol-collector.otel-dev.svc:4317", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return oteltrace.NewNoopTracerProvider(), nil, fmt.Errorf("failed to create gRPC connection to collector: %w", err)
	}

	// Set up a trace exporter
	traceExporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
	if err != nil {
		return oteltrace.NewNoopTracerProvider(), nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Register the trace exporter with a TracerProvider, using a batch
	// span processor to aggregate spans before export.
	bsp := sdktrace.NewBatchSpanProcessor(traceExporter)
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)
	otel.SetTracerProvider(tracerProvider)

	// set global propagator to tracecontext (the default is no-op).
	otel.SetTextMapPropagator(propagation.TraceContext{})

	// Shutdown will flush any remaining spans and shut down the exporter.
	return tracerProvider, tracerProvider.Shutdown, nil
}

type HelloHandler struct {
	ctx context.Context
	response string
}

func (h *HelloHandler) helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, h.response)
	logWithContext(h.ctx).Info("Servicing request", zap.String("response", h.response))
}

type CounterHandler struct {
	ctx context.Context
    counter int
}

func (ct *CounterHandler) counterHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Println(ct.counter)
    ct.counter++
	msg := fmt.Sprintf("Counter: %d", ct.counter)
    fmt.Fprintln(w, msg)
	logWithContext(ct.ctx).Info("Counter", zap.String("response", msg))
}

type NotFoundHandler struct {
	ctx context.Context
}

func (nf *NotFoundHandler) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	    if r.URL.Path != "/" {
            w.WriteHeader(404)
            w.Write([]byte("404 - not found\n"))
			msg := "404 - not found"
	        logWithContext(nf.ctx).Info("NotFound", zap.String("response", msg))
            return
        }
		msg := "This page does nothing, add a '/count' or a '/hello'"
		fmt.Fprintln(w, msg)
	    logWithContext(nf.ctx).Info("Home", zap.String("response", msg))
}

func listenAndServe(ctx context.Context, port string, handler http.Handler) {
	msg := fmt.Sprintf("serving on %s\n", port)
	logWithContext(ctx).Info(msg, zap.String("port", port))
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		msg := fmt.Sprintf("ListenAndServe: " + err.Error())
		logWithContext(ctx).Panic(msg)
	}
}

// propagators returns the recommended set of propagators.
func propagators() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
}

// withTracing adds tracing to requests if the incoming request is sampled
func withTracing(handler http.Handler, tp oteltrace.TracerProvider) http.Handler {
	opts := []otelhttp.Option{
		otelhttp.WithPropagators(propagators()),
		otelhttp.WithPublicEndpoint(),
		otelhttp.WithTracerProvider(tp),
	}
	// With Noop TracerProvider, the otelhttp still handles context propagation.
	// See https://github.com/open-telemetry/opentelemetry-go/tree/main/example/passthrough
	return otelhttp.NewHandler(handler, "OTelHTTP-Example", opts...)
}

func main() {
	ctx :=context.Background()

	tp, shutdown, err := initProvider()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := shutdown(ctx); err != nil {
			log.Fatal("failed to shutdown TracerProvider: %w", err)
		}
	}()

	tracer := otel.Tracer("otel-dev-tracer")

	// Attributes represent additional key-value descriptors that can be bound
	// to a metric observer or recorder.
	commonAttrs := []attribute.KeyValue{
		attribute.String("attrA", "chocolate"),
		attribute.String("attrB", "raspberry"),
		attribute.String("attrC", "vanilla"),
	}
	ctx = newContext(ctx)
	logger = logWithContext(ctx)
	for i := 0; i < 10; i++ {
		_, span := tracer.Start(ctx, fmt.Sprintf("Sample-%d", i), oteltrace.WithAttributes(commonAttrs...))
		msg := fmt.Sprintf("Doing really hard work (%d / 10)\n", i+1)
		logWithContext(ctx).Info(msg)

		<-time.After(time.Second)
	    logWithContext(ctx).Info("Done!")
		span.End()
	}
	helloResponse := os.Getenv("RESPONSE")
	if len(helloResponse) == 0 {
		helloResponse = "Hello OpenShift!"
	}
	hello := &HelloHandler{
		response: helloResponse,
		ctx: ctx,
	}

	count := &CounterHandler{
		ctx: ctx,
		counter: 0,
	}

	notFound := &NotFoundHandler{
		ctx: ctx,
	}

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", hello.helloHandler)
	mux.HandleFunc("/count", count.counterHandler)
	mux.HandleFunc("/", notFound.notFoundHandler)
	handler := withTracing(mux, tp)
	go listenAndServe(ctx, port, handler)

	select {}
}
