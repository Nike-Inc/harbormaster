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
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/Nike-Inc/harbormaster/internal/pkg/validator"
	log "github.com/sirupsen/logrus"
	authenticationapi "k8s.io/api/authentication/v1beta1"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/pkg/api"
	// Installs the necessary API objects for k8s to run
	_ "k8s.io/client-go/pkg/api/install"
	_ "k8s.io/client-go/pkg/apis/authentication/install"
)

// TokenHandler is used for responding to a TokenReview request from the Kubernetes
// API. It's primary use is as an HTTP handler
type TokenHandler struct {
	validator *validator.Validator
}

// NewTokenHandler returns a TokenHandler with the given validator to be used for
// validating and caching token responses
func NewTokenHandler(v *validator.Validator) *TokenHandler {
	return &TokenHandler{
		validator: v,
	}
}

// ValidateTokenReview is the main handler for validating a token review
func (t *TokenHandler) ValidateTokenReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.WithField("method", r.Method).Warn("Invalid HTTP method called")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Add("Allow", "POST")
		return
	}
	review, err := parseTokenReview(r.Body)
	if err != nil {
		log.WithField("error", err.Error()).Warn("Invalid TokenReview body sent")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "malformed TokenReview sent"}`))
		return
	}
	log.Debug("Received TokenReview request. Now validating")
	finalReview, err := t.validator.Validate(r.Context(), review)
	if err != nil {
		if err == validator.ErrorInvalidToken {
			t.reviewError(w, &authenticationapi.TokenReview{}, err.Error(), http.StatusUnauthorized)
			return
		}
		t.reviewError(w, &authenticationapi.TokenReview{}, err.Error(), http.StatusInternalServerError)
		return
	}
	log.WithField("token_review", finalReview).Debug("User authentication successful. Returning TokenReview to apiserver")
	w.WriteHeader(http.StatusOK)
	json.NewSerializer(json.DefaultMetaFactory, nil, nil, false).Encode(finalReview, w)

}

// reviewError is a helper for sending back an error or unauthenticated body to the k8s API
func (t *TokenHandler) reviewError(w http.ResponseWriter, review *authenticationapi.TokenReview, message string, errorCode int) {
	review.Status.Error = message
	review.Status.Authenticated = false
	w.WriteHeader(errorCode)
	json.NewSerializer(json.DefaultMetaFactory, nil, nil, false).Encode(review, w)
	return
}

// HealthCheck is a simple endpoint to ping for server health
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// parseTokenReview takes an HTTP request body, and attempts to parse it to a
// TokenReview object
func parseTokenReview(body io.ReadCloser) (*authenticationapi.TokenReview, error) {
	defer body.Close()
	rawBody, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("Error while reading webhook body: %s", err)
	}
	// Deserialize into the kubernetes object
	var tokenReview = &authenticationapi.TokenReview{}
	if _, _, err = api.Codecs.UniversalDeserializer().Decode(rawBody, nil, tokenReview); err != nil {
		return nil, fmt.Errorf("Invalid body sent, unable to deserialize: %s", err)
	}
	return tokenReview, nil
}
