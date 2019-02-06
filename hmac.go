package hmiddle

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"strings"
)

type hmacAuth struct {
	h                http.Handler
	secretLookupFunc SecretLookupFunction
	msgContentFunc   MessageContentFunction
	unauthHandler    http.Handler
	header           string
}

// SecretLookupFunction takes the public key id string and uses it to look up the
// secret key. An empty string should be returned if the secret key cannot be
// found for any reason.
type SecretLookupFunction func(key string) string

// MessageContentFunction is a function that will return the payload content that
// is used to compute the signature. If you read the request's body in your
// function, you are responsible for closing the original Body and creating a new
// Body with the content from the original Body
type MessageContentFunction func(r *http.Request) string

// Satisfies the http.Handler interface for hmacAuth.
func (a hmacAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authenticated, apiID := a.authenticate(r)
	// Check that the provided details match
	if !authenticated {
		a.unauthHandler.ServeHTTP(w, r)
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

	if a.secretLookupFunc == nil {
		return false, ""
	}

	// Confirm the request is sending the header
	auth := r.Header.Get(a.header)
	if auth == "" {
		return false, ""
	}

	creds := strings.SplitN(auth, ":", 2)
	if len(creds) != 2 {
		return false, ""
	}

	secret := a.secretLookupFunc(creds[0])
	if secret == "" {
		return false, ""
	}

	// Decode the signature header
	decoded, err := base64.StdEncoding.DecodeString(creds[1])
	if err != nil {
		return false, ""
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(a.msgContentFunc(r)))

	if !hmac.Equal(decoded, mac.Sum(nil)) {
		return false, ""
	}

	return true, creds[0]
}

//MessageContentMethodURL is a MessageContentFunction that returns the request's
// method and url concatenated together as the message content. This is the default
// MessageContentFunction
func MessageContentMethodURL(r *http.Request) string {
	return r.Method + r.URL.String()
}

// MessageContentMethodURLBody is a MessageContentFunction that returns the
// request's method, url, and body concatenated together as the message content.
// The body is separated from the method and url by a newline
func MessageContentMethodURLBody(r *http.Request) string {
	body, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	return r.Method + r.URL.String() + "\n" + string(body)
}

// defaultUnauthorizedHandler provides a default HTTP 401 Unauthorized response.
func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

// HMACAuth returns an http middleware function that provides HMAC authentication
func HMACAuth(opts ...Option) func(http.Handler) http.Handler {
	o := &options{
		unauthHandler:  http.HandlerFunc(defaultUnauthorizedHandler),
		header:         "Authorization",
		msgContentFunc: MessageContentMethodURL,
	}

	for _, opt := range opts {
		opt(o)
	}

	return func(h http.Handler) http.Handler {
		return hmacAuth{
			h:                h,
			secretLookupFunc: o.secretLookupFunc,
			unauthHandler:    o.unauthHandler,
			header:           o.header,
			msgContentFunc:   o.msgContentFunc,
		}
	}
}
