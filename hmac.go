package hmiddle

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
)

type hmacAuth struct {
	h    http.Handler
	opts AuthOptions
}

// AuthOptions stores the configuration for HMAC Authentication
//
// A http.Handler may also be passed to UnauthorizedHandler to override the
// default error handler if you wish to serve a custom template/response.
type AuthOptions struct {
	SecretLookupFunc    func(key string) string
	UnauthorizedHandler http.Handler
}

// Satisfies the http.Handler interface for hmacAuth.
func (a hmacAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if we have a user-provided error handler, else set a default
	if a.opts.UnauthorizedHandler == nil {
		a.opts.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	}

	authenticated, apiID := a.authenticate(r)
	// Check that the provided details match
	if !authenticated {
		a.opts.UnauthorizedHandler.ServeHTTP(w, r)
		return
	}

	a.h.ServeHTTP(w, r.WithContext(NewContext(r.Context(), apiID)))
}

// authenticate retrieves and then validates the request.
// Returns 'false' if the request has not successfully authenticated.
func (a *hmacAuth) authenticate(r *http.Request) (bool, string) {
	if r == nil {
		return false, ""
	}

	if a.opts.SecretLookupFunc == nil {
		return false, ""
	}

	// Confirm the request is sending Basic Authentication credentials.
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false, ""
	}

	creds := strings.SplitN(auth, ":", 2)
	if len(creds) != 2 {
		return false, ""
	}

	secret := a.opts.SecretLookupFunc(creds[0])
	if secret == "" {
		return false, ""
	}

	// Decode the Authorization header
	decoded, err := base64.StdEncoding.DecodeString(creds[1])
	if err != nil {
		return false, ""
	}

	// TODO: Provide a way to override the message creation. Also, consider including the request body
	// in the message.
	message := r.Method + r.URL.String()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(decoded, expectedMAC) {
		return false, ""
	}

	return true, creds[0]
}

// defaultUnauthorizedHandler provides a default HTTP 401 Unauthorized response.
func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

// HMACAuth returns an http middleware function that provides HMAC authentication
func HMACAuth(o AuthOptions) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return hmacAuth{h, o}
	}
}
