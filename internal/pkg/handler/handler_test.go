/*
Copyright 2017 Nike Inc.

Licensed under the Apache License, Version 2.0 (the License);
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an AS IS BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package handler

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Nike-Inc/harbormaster/internal/pkg/validator"
	authenticationapi "k8s.io/api/authentication/v1beta1"
)

var hasNetwork bool

var oktaURL = url.URL{
	// We don't want to specify a port on here or else the issuer URL doesn't match
	// what the provider sends back (e.g. https://nike.okta.com vs https://nike.okta.com:443)
	Host:   "nike.okta.com",
	Scheme: "https",
}

// checkNetworkConnectivity checks to see if oktaURL is reachable before running a test
func checkNetworkConnectivity() {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:443", oktaURL.Host), time.Second*3)
	if err != nil {
		// Explicitly setting here for clarity sake
		hasNetwork = false
		return
	}
	hasNetwork = true
	conn.Close()
}

func init() {
	checkNetworkConnectivity()
}

func getReaderFromString(data string) io.ReadCloser {
	return ioutil.NopCloser(bytes.NewReader([]byte(data)))
}

func TestNewTokenHandler(t *testing.T) {
	if !hasNetwork {
		t.Skipf("Unable to contact %s, skipping test", oktaURL.String())
	}
	v, err := validator.New(validator.IssuerURL(oktaURL.String()))
	if err != nil {
		t.Fatalf("Error trying to set up validator, exiting test: %s", err)
	}
	th := NewTokenHandler(v)
	if th == nil {
		t.Error("Got nil token handler")
	}
}

func TestParseTokenReview(t *testing.T) {
	var tokenReviewRequest = `{
  "apiVersion": "authentication.k8s.io/v1beta1",
  "kind": "TokenReview",
  "spec": {
    "token": "engage"
  }
}`

	var badTokenReviewRequest = `{ "bad_json":`
	t.Run("valid body should parse", func(t *testing.T) {
		body := getReaderFromString(tokenReviewRequest)
		review, err := parseTokenReview(body)
		if err != nil {
			t.Errorf("Got error while parsing TokenReview: %s", err)
		}
		if review == nil {
			t.Error("Got nil token review")
		}
	})
	t.Run("invalid object should error", func(t *testing.T) {
		body := getReaderFromString(badTokenReviewRequest)
		review, err := parseTokenReview(body)
		if err == nil {
			t.Error("Should have errored")
		}
		if review != nil {
			t.Error("Token review is not nil")
		}
	})
}

func TestHealthCheck(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8000/healthz", nil)
	w := httptest.NewRecorder()
	HealthCheck(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected a %d status, got %d instead", http.StatusOK, resp.StatusCode)
	}
}
func TestReviewError(t *testing.T) {
	if !hasNetwork {
		t.Skipf("Unable to contact %s, skipping test", oktaURL)
	}
	th := &TokenHandler{}
	var responseError = &authenticationapi.TokenReview{}
	var errorMessage = "warp drive failure"
	w := httptest.NewRecorder()
	th.reviewError(w, responseError, errorMessage, http.StatusInternalServerError)
	resp := w.Result()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected a %d status, got %d instead", http.StatusInternalServerError, resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("Error while decoding body: %s", err)
	}
	strBody := string(body)
	if !strings.Contains(strBody, errorMessage) {
		t.Errorf("Response body does contain error. \nExpected to find: %s\nGot: %s", errorMessage, strBody)
	}
}
