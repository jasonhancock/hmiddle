package hmiddle

import "net/http"

type options struct {
	secretLookupFunc SecretLookupFunction
	unauthHandler    http.Handler
}

// Option is used to customize the service
type Option func(*options)

// WithSecretLookupFunction sets up the secret lookup function to use
func WithSecretLookupFunction(fn SecretLookupFunction) Option {
	return func(o *options) {
		o.secretLookupFunc = fn
	}
}

// WithUnauthHandler sets up the http handler to call when a request isn't authorized
func WithUnauthHandler(h http.Handler) Option {
	return func(o *options) {
		o.unauthHandler = h
	}
}
