package health

import (
	"context"
	"io/ioutil"
	"net/http"
	"sync"

	chassishttp "github.com/90poe/service-chassis/http"
)

const (
	DefaultPort = 8888
)

func ConnectHealthCheckServiceWithCtx(ctx context.Context,
	wg *sync.WaitGroup,
	port int,
	healthChecks []func() error,
	readinessChecks []func() error,
) *http.Server {
	return chassishttp.ConnectServiceWithContext(ctx, wg, port, Handler(healthChecks, readinessChecks))
}

func ConnectHealthCheckService(
	wg *sync.WaitGroup,
	port int,
	healthChecks []func() error,
	readinessChecks []func() error,
) *http.Server {
	return chassishttp.ConnectService(wg, port, Handler(healthChecks, readinessChecks))
}

func Handler(healthChecks []func() error, readinessChecks []func() error) http.Handler {
	handler := http.NewServeMux()
	handler.HandleFunc("/proto", serveProto)
	handler.HandleFunc("/version", serveVersion)
	handler.HandleFunc("/sha", serveSha)
	handler.HandleFunc("/", func(res http.ResponseWriter, _ *http.Request) { serveCheck(res, healthChecks) })
	handler.HandleFunc("/ready", func(res http.ResponseWriter, _ *http.Request) { serveCheck(res, readinessChecks) })
	return handler
}

func serveCheck(response http.ResponseWriter, checks []func() error) {
	writtenHeader := false
	for _, check := range checks {
		if err := check(); err != nil {
			if !writtenHeader {
				response.WriteHeader(http.StatusInternalServerError)
				writtenHeader = true
			}
			response.Write([]byte(err.Error())) // nolint
			response.Write([]byte("\n\n"))      // nolint
		}
	}

	if !writtenHeader {
		response.WriteHeader(http.StatusNoContent)
	}
}

func serveProto(response http.ResponseWriter, _ *http.Request) {
	writeFile("service.proto", response)
}

func serveVersion(response http.ResponseWriter, _ *http.Request) {
	writeFile("version", response)
}

func serveSha(response http.ResponseWriter, _ *http.Request) {
	writeFile("sha", response)
}

func writeFile(file string, response http.ResponseWriter) {
	if proto, err := ioutil.ReadFile(file); err == nil { // nolint
		response.WriteHeader(http.StatusOK)
		response.Write(proto) // nolint
	} else {
		response.WriteHeader(http.StatusNoContent)
	}
}
