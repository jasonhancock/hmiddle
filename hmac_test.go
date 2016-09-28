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
	is := is.New(t)

	apiId := "apikey123"
	apiSecret := "012345678900123456789001234567890ab"

	r := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "/some/path",
		},
	}

	authOpts := AuthOptions{
		SecretLookupFunc: func(k string) string {
			if k == apiId {
				return apiSecret
			}
			return ""
		},
	}

	a := &hmacAuth{opts: authOpts}

	// Should not succeed wwhen http.Request is nil
	res, id := a.authenticate(nil)
	is.False(res)
	is.Equal(id, "")

	// Provide a request, but without an Authorization header
	res, id = a.authenticate(r)
	is.False(res)
	is.Equal(id, "")

	// Initialise the map for HTTP headers
	r.Header = http.Header(make(map[string][]string))

	// Set a malformed/bad header
	r.Header.Set("Authorization", "    foobar")
	res, id = a.authenticate(r)
	is.False(res)
	is.Equal(id, "")

	// Generate the signature, add the header
	message := r.Method + r.URL.Path
	mac := hmac.New(sha256.New, []byte(apiSecret))
	mac.Write([]byte(message))
	hash := mac.Sum(nil)
	signature := base64.StdEncoding.EncodeToString(hash)
	r.Header.Set("Authorization", apiId+":"+signature)

	// Test correct credentials
	res, id = a.authenticate(r)
	is.True(res)
	is.Equal(id, apiId)

	// Test incorrect credentials
	mac = hmac.New(sha256.New, []byte(apiSecret+"badsecret"))
	mac.Write([]byte(message))
	hash = mac.Sum(nil)
	signature = base64.StdEncoding.EncodeToString(hash)
	r.Header.Set("Authorization", apiId+":"+signature)

	res, id = a.authenticate(r)
	is.False(res)
	is.Equal(id, "")

	// Test unknown apiId
	mac = hmac.New(sha256.New, []byte(apiSecret))
	mac.Write([]byte(message))
	hash = mac.Sum(nil)
	signature = base64.StdEncoding.EncodeToString(hash)
	r.Header.Set("Authorization", "foo"+":"+signature)

	res, id = a.authenticate(r)
	is.False(res)
	is.Equal(id, "")
}

func TestHMACAuthenticateWithoutFunc(t *testing.T) {
	is := is.New(t)

	apiId := "apikey123"
	apiSecret := "012345678900123456789001234567890ab"

	r := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "/some/path",
		},
	}

	authOpts := AuthOptions{}
	a := &hmacAuth{opts: authOpts}

	// Initialise the map for HTTP headers
	r.Header = http.Header(make(map[string][]string))

	// Generate the signature, add the header
	message := r.Method + r.URL.Path
	mac := hmac.New(sha256.New, []byte(apiSecret))
	mac.Write([]byte(message))
	hash := mac.Sum(nil)
	signature := base64.StdEncoding.EncodeToString(hash)
	r.Header.Set("Authorization", apiId+":"+signature)

	res, id := a.authenticate(r)
	is.False(res)
	is.Equal(id, "")
}
