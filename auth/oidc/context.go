package oidc

import (
	"context"

	"google.golang.org/api/idtoken"
)

// contextKey is the context key type private to this package. It is
// unexported so it cannot collide with other packages' keys.
type contextKey int

const payloadContextKey contextKey = iota

// withPayload stores the payload of a verified OIDC token in the context.
func withPayload(ctx context.Context, payload *idtoken.Payload) context.Context {
	return context.WithValue(ctx, payloadContextKey, payload)
}

// PayloadFromContext returns the verified payload stored by the Verifier.
// It can be used to identify the calling service account, for example.
func PayloadFromContext(ctx context.Context) (*idtoken.Payload, bool) {
	payload, ok := ctx.Value(payloadContextKey).(*idtoken.Payload)
	return payload, ok && payload != nil
}
