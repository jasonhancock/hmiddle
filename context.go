package hmiddle

import "context"

type contextKey int

const idContextKey contextKey = iota

// FromContextID returns the public key ID from the context
func FromContextID(ctx context.Context) (string, bool) {
	value, ok := ctx.Value(idContextKey).(string)
	if !ok {
		return "", false
	}
	return value, true
}

// NewContext returns a new context with the id set
func NewContext(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, idContextKey, id)
}
