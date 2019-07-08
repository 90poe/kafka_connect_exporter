package context

import (
	"context"
	"github.com/90poe/service-chassis/authorisation"
)

type contextKey int

//https://stackoverflow.com/questions/40891345/fix-should-not-use-basic-type-string-as-key-in-context-withvalue-golint
const (
	correlationIDContextKey contextKey = iota
)

func SetCorrelationID(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, correlationIDContextKey, correlationID)
}

func GetCorrelationID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(correlationIDContextKey).(string)
	return id, ok
}

// Deprecated: authorisation.GetServiceTokenKJwt and authorisation.AddBearerTokenPrefix
func GetAuthorization(ctx context.Context) (string, bool) {
	serviceTokenJwt, ok := authorisation.GetServiceTokenJwt(ctx)
	if !ok {
		return "", false
	}

	return authorisation.AddBearerTokenPrefix(serviceTokenJwt), true
}
