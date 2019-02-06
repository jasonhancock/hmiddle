package hmiddle

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/cheekybits/is"
)

func TestHMACAuthenticateWithFunc(t *testing.T) {
	apiID := "apikey123"
	apiSecret := "012345678900123456789001234567890ab"

	r := &http.Request{
		Method: http.MethodGet,
		URL: &url.URL{
			Path: "/some/path",
		},
		Header: make(http.Header),
	}

	secretFunc := func(k string) string {
		if k == apiID {
			return apiSecret
		}
		return ""
	}

	a := &hmacAuth{
		secretLookupFunc: secretFunc,
		header:           "Authorization",
	}

	t.Run("nil request", func(t *testing.T) {
		is := is.New(t)
		res, id := a.authenticate(nil)

		// Should not succeed when http.Request is nil
		is.False(res)
		is.Equal(id, "")
	})

	t.Run("no auth header", func(t *testing.T) {
		is := is.New(t)
		// Provide a request, but without an Authorization header
		res, id := a.authenticate(r)
		is.False(res)
		is.Equal(id, "")
	})

	t.Run("malformed auth header", func(t *testing.T) {
		is := is.New(t)
		// Set a malformed/bad header
		r.Header.Set("Authorization", "    foobar")
		res, id := a.authenticate(r)
		is.False(res)
		is.Equal(id, "")
	})

	genSig := func(secret string) string {
		message := r.Method + r.URL.Path
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(message))
		hash := mac.Sum(nil)
		return base64.StdEncoding.EncodeToString(hash)
	}

	t.Run("correct credentials", func(t *testing.T) {
		is := is.New(t)
		r.Header.Set("Authorization", apiID+":"+genSig(apiSecret))

		// Test correct credentials
		res, id := a.authenticate(r)
		is.True(res)
		is.Equal(id, apiID)
	})

	t.Run("correct credentials non-default header", func(t *testing.T) {
		is := is.New(t)
		headerSave := a.header
		a.header = "X-Signature"
		defer func() {
			r.Header.Del(a.header)
			a.header = headerSave
		}()

		r.Header.Del(headerSave)
		r.Header.Set(a.header, apiID+":"+genSig(apiSecret))

		// Test correct credentials
		res, id := a.authenticate(r)
		is.True(res)
		is.Equal(id, apiID)
	})

	t.Run("incorrect creds", func(t *testing.T) {
		is := is.New(t)
		r.Header.Set("Authorization", apiID+":"+genSig("badsecret"))
		res, id := a.authenticate(r)
		is.False(res)
		is.Equal(id, "")
	})

	t.Run("unknown appID", func(t *testing.T) {
		// Test unknown apiID
		is := is.New(t)
		r.Header.Set("Authorization", "foo"+":"+genSig(apiSecret))
		res, id := a.authenticate(r)
		is.False(res)
		is.Equal(id, "")
	})

	t.Run("without lookup func", func(t *testing.T) {
		is := is.New(t)
		a.secretLookupFunc = nil
		r.Header.Set("Authorization", apiID+":"+genSig(apiSecret))
		res, id := a.authenticate(r)
		is.False(res)
		is.Equal(id, "")
	})
}
