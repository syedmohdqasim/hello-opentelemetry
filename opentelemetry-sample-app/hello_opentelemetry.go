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
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"time"

	log "github.com/sirupsen/logrus"

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

func logWithContext(span oteltrace.Span) log.Fields {
	return log.Fields{
		"span_id":  span.SpanContext().SpanID().String(),
		"trace_id": span.SpanContext().TraceID().String(),
	}
}

// Initializes an OTLP exporter, and configures the corresponding trace and
// metric providers.
func initProvider() (func(context.Context) error, error) {
	log.Infof("Configuring TracerProvider")
	ctx := context.Background()
	res, err := resource.New(ctx,
		resource.WithAttributes(
			// the service name used to display traces in backends
			semconv.ServiceNameKey.String("test-service"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "otelcol-collector-headless.otel-dev.svc.cluster.local:4317", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection to collector: %w", err)
	}

	// Set up a trace exporter
	traceExporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
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

	log.Infof("TracerProvider configured")
	// Shutdown will flush any remaining spans and shut down the exporter.
	return tracerProvider.Shutdown, nil
}

type HelloHandler struct {
	ctx      context.Context
	response string
}

func (h *HelloHandler) helloHandler(w http.ResponseWriter, r *http.Request) {
	tracer := otel.Tracer("hello")
	_, span := tracer.Start(h.ctx, "helloHandler")
	defer span.End()
	fmt.Fprintln(w, h.response)
	log.WithFields(logWithContext(span)).Info("Hello request", zap.String("response", h.response))
}

type CounterHandler struct {
	ctx     context.Context
	counter int
}

func (ct *CounterHandler) counterHandler(w http.ResponseWriter, r *http.Request) {
	tracer := otel.Tracer("count")
	_, span := tracer.Start(ct.ctx, "counterHandler")
	defer span.End()
	fmt.Println(ct.counter)
	ct.counter++
	msg := fmt.Sprintf("Counter: %d", ct.counter)
	fmt.Fprintln(w, msg)
	log.WithFields(logWithContext(span)).Info("Counter", zap.String("response", msg))
}

type NotFoundHandler struct {
	ctx context.Context
}

func (nf *NotFoundHandler) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	tracer := otel.Tracer("notfound")
	_, span := tracer.Start(nf.ctx, "notFoundHandler")
	defer span.End()
	if r.URL.Path != "/" {
		w.WriteHeader(404)
		w.Write([]byte("404 - not found\n"))
		msg := "404 - not found"
		log.WithFields(logWithContext(span)).Info("NotFound", zap.String("response", msg))
		return
	}
	msg := "This page does nothing, add a '/count' or a '/hello'"
	fmt.Fprintln(w, msg)
	log.WithFields(logWithContext(span)).Info("Home", zap.String("response", msg))
}

func listenAndServe(ctx context.Context, port, uid string, handler http.Handler) {
	attrs := []attribute.KeyValue{
		attribute.String("uid", uid),
	}
	log.Infof("serving on %s", port)
	tracer := otel.Tracer("listenandserve")
	_, span := tracer.Start(ctx, "listenandserve", oteltrace.WithAttributes(attrs...))
	defer span.End()
	_, err := os.Stat("/etc/tls-config/tls.crt")
	if err == nil {
		if err := http.ListenAndServeTLS(":"+port, "/etc/tls-config/tls.crt", "/etc/tls-config/tls.key", handler); err != nil {
			msg := fmt.Sprintf("ListenAndServe: " + err.Error())
			log.WithFields(logWithContext(span)).Panic(msg)
		}
		return
	}
	if errors.Is(err, os.ErrNotExist) {
		if err := http.ListenAndServe(":"+port, handler); err != nil {
			msg := fmt.Sprintf("ListenAndServe: " + err.Error())
			log.WithFields(logWithContext(span)).Panic(msg)
		}
		return
	}
	log.Fatalf("failed to start serving: %w", err)
}

// propagators returns the recommended set of propagators.
func propagators() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
}

// withTracing adds tracing to requests if the incoming request is sampled
func withTracing(handler http.Handler) http.Handler {
	// With Noop TracerProvider, the otelhttp still handles context propagation.
	opts := []otelhttp.Option{
		otelhttp.WithPropagators(propagators()),
		otelhttp.WithPublicEndpoint(),
		otelhttp.WithTracerProvider(otel.GetTracerProvider()),
	}
	return otelhttp.NewHandler(handler, "otel-example", opts...)
}

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})

	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
}

func main() {
	log.Infof("Starting server")
	ctx := context.Background()
	shutdown, err := initProvider()
	if err != nil {
		log.Fatalf("failed to configure TracerProvider: %w", err)
	}
	defer func() {
		if err := shutdown(ctx); err != nil {
			log.Fatalf("failed to shutdown TracerProvider: %w", err)
		}
	}()

	tracer := otel.Tracer("main")

	// Attributes represent additional key-value descriptors that can be bound
	// to a metric observer or recorder.
	commonAttrs := []attribute.KeyValue{
		attribute.String("attrA", "info"),
		attribute.String("attrB", "important info"),
		attribute.String("attrC", "more important info"),
	}
	uid, err := user.Current()
	if err != nil {
		log.Fatalf("failed to get current user: %w", err)
	}

	_, span := tracer.Start(ctx, fmt.Sprintf("user: %s", uid.Uid), oteltrace.WithAttributes(commonAttrs...))
	defer span.End()
	msg := fmt.Sprintf("UID: %s Time: %s", uid.Uid, time.Now().String())
	log.WithFields(logWithContext(span)).Info(msg)

	helloResponse := os.Getenv("RESPONSE")
	if len(helloResponse) == 0 {
		helloResponse = "Hello OpenTelemetry!"
	}
	hello := &HelloHandler{
		response: helloResponse,
		ctx:      ctx,
	}

	count := &CounterHandler{
		ctx:     ctx,
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
	handler := withTracing(mux)
	go listenAndServe(ctx, port, uid.Uid, handler)

	select {}
}
