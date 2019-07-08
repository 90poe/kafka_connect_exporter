package http

import (
	"context"
	"fmt"
	"github.com/90poe/service-chassis/authorisation"
	"net/http"
	"sync"

	chassiscontext "github.com/90poe/service-chassis/context"
	"github.com/90poe/service-chassis/correlation"
	"github.com/satori/go.uuid"
)

const (
	DefaultPort = 8080

	authHeaderKey = "authorization"

	DefaultPublicURLForOutboundGetTest = "http://www.google.com"
)

func PanicOnFailureToGet200(testURLs ...string) {
	for _, url := range testURLs {
		// FIXME: G107: Potential HTTP request made with variable url (gosec)
		response, err := http.Get(url) // nolint: gosec

		if err != nil {
			panic(err)
		}

		if response.StatusCode != http.StatusOK {
			panic(fmt.Sprintf("Error response not 200 : %v : %v", url, response.Status))
		}
	}
}

func ConnectService(wg *sync.WaitGroup, port int, handler http.Handler) *http.Server {
	server := &http.Server{Addr: fmt.Sprintf("0.0.0.0:%v", port), Handler: handler}

	wg.Add(1)
	go func() {
		server.ListenAndServe() // nolint
		wg.Done()
	}()

	return server
}

func ConnectServiceWithContext(ctx context.Context, wg *sync.WaitGroup, port int, handler http.Handler) *http.Server {
	server := ConnectService(wg, port, handler)

	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background()) // nolint
	}()

	return server
}

func ReadCorrelationIDAndAuthorizationFromHeaderAndAppendToContext(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		correlationID := r.Header.Get(correlation.CorrelationIDFieldName)
		if len(correlationID) > 0 {
			r = r.WithContext(chassiscontext.SetCorrelationID(r.Context(), correlationID))
		} else {
			r = r.WithContext(chassiscontext.SetCorrelationID(r.Context(), uuid.NewV4().String()))
		}

		authorizationValue := r.Header.Get(authHeaderKey)
		if authorizationValue != "" {
			bearerToken, err := authorisation.NewBearerToken(authorizationValue)
			if err == nil {
				r = r.WithContext(authorisation.SetServiceTokenJwt(r.Context(), bearerToken.ServiceTokenJwt()))
			}
		}

		h.ServeHTTP(w, r)
	})
}
func AppendAuthorizationKeyFromContextToHTTPRequest(ctx context.Context, r *http.Request) {
	if serviceTokenJwt, ok := authorisation.GetServiceTokenJwt(ctx); ok {
		r.Header.Set(authHeaderKey, authorisation.AddBearerTokenPrefix(serviceTokenJwt))
	}
}

func AppendCorrelationIDToHTTPRequest(ctx context.Context, r *http.Request) {
	if correlationID, ok := chassiscontext.GetCorrelationID(ctx); ok {
		r.Header.Set(correlation.CorrelationIDFieldName, correlationID)
	}
}

func GetAuthHeader(r *http.Request) string {
	return r.Header.Get(authHeaderKey)
}
