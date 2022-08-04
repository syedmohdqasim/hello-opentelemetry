## Hello, Kubernetes, OpenShift & OpenTelemetry! ##

This example will serve an HTTP response of "Hello OpenTelemetry!".

The response message can be set by using the RESPONSE environment
variable.  You will need to edit the pod definition and add an
environment variable to the container definition and run the new pod.

The hello response is served at `/hello`
There is also a counter at `/count`

```bash
curl service-address:8080/hello or route/hello
Hello OpenTelemetry!
```

### Create the example application

```
All resources are expected to be created in the `otel-dev` namespace. Update the definitions accordingly if not running in
this namespace.
```

Kubernetes cluster

```bash
kubectl apply -f https://raw.githubusercontent.com/sallyom/golang-ex/master/opentelemetry-sample-app/sample-app-w-ingress.yaml
```

OpenShift cluster

```bash
kubectl apply -f https://raw.githubusercontent.com/sallyom/golang-ex/master/opentelemetry-sample-app/sample-app-w-route.yaml
```

### View OpenTelemetry trace data

The application is instrumented to generate OpenTelemetry spans and logs with the span & trace id injected.
To view the traces, if the OpenTelemetry Operator & the Jaeger Operator are running in the cluster, simply
create an OpenTelemetryCollector instance and a Jaeger instance with the following commands.

*The following commands assume the OpenTelemetry Operator & Jaeger Operator are running in the cluster*

```bash
kubectl apply -f https://raw.githubusercontent.com/sallyom/golang-ex/master/opentelemetry-sample-app/otelcol.yaml
kubectl apply -f https://raw.githubusercontent.com/sallyom/golang-ex/master/opentelemetry-sample-app/jaeger.yaml
```

To view the traces, access the route for the Jaeger UI. A `test-service` should appear.
