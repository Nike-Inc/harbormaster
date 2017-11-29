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

package validator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Nike-Inc/harbormaster/pkg/graph"
	"github.com/Nike-Inc/harbormaster/pkg/groups"
	"github.com/allegro/bigcache"
	oidc "github.com/coreos/go-oidc"
	log "github.com/sirupsen/logrus"
	authenticationapi "k8s.io/api/authentication/v1beta1"
	// These register the API objects with the deserializer
	_ "k8s.io/client-go/pkg/api/install"
	_ "k8s.io/client-go/pkg/apis/authentication/install"
)

var (
	// ErrorClaimNotFound indicates the given key was not found in the claims
	ErrorClaimNotFound = fmt.Errorf("Claim not found")
	// ErrorInvalidToken means we were unable to validate a given token
	ErrorInvalidToken = fmt.Errorf("Invalid token")
)

const (
	// DefaultMaxCacheMemory is the default amount of memory (in MB) to allocate to the cache
	DefaultMaxCacheMemory = 1024
	// DefaultCacheDuration is the default life of a cache entry
	DefaultCacheDuration = 1 * time.Hour
	// DefaultIssuerURL is the default URL for Okta
	DefaultIssuerURL = "https://example.oktapreview.com"
	// DefaultUsernameClaim is the default claim used to obtain the username
	DefaultUsernameClaim = "email"
	// DefaultGroupsClaim is the default claim used to obtain the groups
	DefaultGroupsClaim = "groups"
)

// Validator is used to validate an ID token and cache group responses
type Validator struct {
	usernameClaim string
	groupsClaim   string
	issuerURL     string
	clientID      string
	cacheConf     bigcache.Config // We add this so we can expose configurability to the user with func opts
	cache         *bigcache.BigCache
	verifier      *oidc.IDTokenVerifier
	groupGetter   groups.Getter
}

// Option represents an option for Validator. This returns an error in case we
// want to do more advanced option stuff in the future
type Option func(*Validator) error

// claims represents a map of claims provided with a JWT
type claims map[string]interface{}

// UsernameClaim sets a username claim for a validator
func UsernameClaim(username string) Option {
	return func(v *Validator) error {
		v.usernameClaim = username
		return nil
	}
}

// GroupsClaim sets a group claim for a validator
func GroupsClaim(group string) Option {
	return func(v *Validator) error {
		v.groupsClaim = group
		return nil
	}
}

// CacheSize sets the max cache size
func CacheSize(maxCacheSize int) Option {
	return func(v *Validator) error {
		v.cacheConf.HardMaxCacheSize = maxCacheSize
		return nil
	}
}

// CacheExpiry sets the max cache size
func CacheExpiry(expiry time.Duration) Option {
	return func(v *Validator) error {
		v.cacheConf.LifeWindow = expiry
		return nil
	}
}

// IssuerURL sets the OIDC issuer URL
func IssuerURL(issuerURL string) Option {
	return func(v *Validator) error {
		v.issuerURL = issuerURL
		return nil
	}
}

// ClientID sets the OIDC issuer URL
func ClientID(clientID string) Option {
	return func(v *Validator) error {
		v.clientID = clientID
		return nil
	}
}

// GraphGetter takes a client ID and secret to log in to the MS Graph API
// for additional user information
func GraphGetter(clientID, clientSecret, tenantName string) Option {
	return func(v *Validator) error {
		u, err := graph.New(clientID, clientSecret, tenantName)
		if err != nil {
			return err
		}
		v.groupGetter = u
		return nil
	}
}

// New creates a new validator object
func New(options ...Option) (*Validator, error) {
	validator := &Validator{
		usernameClaim: DefaultUsernameClaim,
		groupsClaim:   DefaultGroupsClaim,
		issuerURL:     DefaultIssuerURL,
		cacheConf:     bigcache.DefaultConfig(DefaultCacheDuration),
	}
	for _, opt := range options {
		err := opt(validator)
		if err != nil {
			return nil, err
		}
	}
	oidcConfig := &oidc.Config{ClientID: validator.clientID}
	provider, err := oidc.NewProvider(context.Background(), validator.issuerURL)
	if err != nil {
		return nil, fmt.Errorf("Unable to create oidc provider: %s", err)
	}
	cache, err := bigcache.NewBigCache(validator.cacheConf)
	if err != nil {
		return nil, fmt.Errorf("Error trying to initialize cache: %s", err)
	}
	validator.cache = cache
	validator.verifier = provider.Verifier(oidcConfig)
	// TODO(taylor): Figure out how to use a typer to serialize json properly.
	return validator, nil
}

// Validate takes a TokenReview request with the Token field set and validates
// the token. It returns a fully populated TokenReview request with all user
// information or an error if there was a validation error. This also requires
// a context to be passed (generally that of the request)
func (v *Validator) Validate(ctx context.Context, review *authenticationapi.TokenReview) (*authenticationapi.TokenReview, error) {
	token, err := v.verifier.Verify(ctx, review.Spec.Token)
	if err != nil {
		log.WithField("error", err.Error()).Warn("error parsing token")
		return nil, ErrorInvalidToken
	}
	claims, err := getClaims(token)
	if err != nil {
		log.WithField("error", err.Error()).Error("error parsing claims")
		return nil, fmt.Errorf("Error parsing claims: %s", err)
	}
	finalReview, err := claims.ReviewFromClaims(v.usernameClaim, v.groupsClaim, v.groupGetter == nil)
	if err != nil {
		log.WithField("error", err.Error()).Error("error while trying to create TokenReview")
		return nil, fmt.Errorf("Unable to create TokenReview: %s", err)
	}

	// Now that we have the final username and group list, get additional groups
	// if a group getter is set
	if v.groupGetter != nil {
		addlGroups, err := v.getGroups(finalReview.Status.User.Username)
		if err != nil {
			log.WithField("error", err.Error()).Error("unable to fetch user groups from AD")
			return nil, fmt.Errorf("Unable to fetch user groups from AD: %s", err)
		}
		// TODO(taylor): Should we try to get a unique list?
		finalReview.Status.User.Groups = append(finalReview.Status.User.Groups, addlGroups...)
	}

	return finalReview, nil
}

func (v *Validator) getGroups(username string) ([]string, error) {
	// Check the cache first
	if v, err := v.cache.Get(username); err == nil {
		log.WithField("user", username).Debug("found user in cache, returning group list")
		var groupList = []string{}
		err := json.Unmarshal(v, &groupList)
		// This shouldn't error, but just in case...
		if err != nil {
			return nil, err
		}
		return groupList, nil
	}

	log.WithField("user", username).Debugf("user is not in cache, fetching groups using %s getter", v.groupGetter.Name())
	// If it isn't in the cache, look it up
	groups, err := v.groupGetter.GetGroups(username)
	if err != nil {
		return nil, err
	}

	// Encode the data for caching
	encodedData, err := json.Marshal(&groups)
	if err != nil {
		// Not a critical error so just log the warning here
		log.WithField("error", err.Error()).Warn("error while encoding data for cache")
	}
	err = v.cache.Set(username, encodedData)
	if err != nil {
		// Not a critical error so just log the warning here
		log.WithField("error", err.Error()).Warn("error while writing to cache")
	}
	return groups, nil
}

// GetClaims returns a Claims object
func getClaims(token *oidc.IDToken) (claims, error) {
	var c = claims{}
	err := token.Claims(&c)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling claims: %s", err)
	}
	return c, nil
}

// ReviewFromClaims creates a new TokenReview object from the claims object
// groupsRequired specifies whether or not the groups claim must be present in
// the claims object
func (c claims) ReviewFromClaims(usernameClaim, groupsClaim string, groupsRequired bool) (*authenticationapi.TokenReview, error) {
	var review = &authenticationapi.TokenReview{
		Status: authenticationapi.TokenReviewStatus{
			Authenticated: true,
		},
	}
	username, err := c.String(usernameClaim)
	if err != nil {
		log.WithFields(log.Fields{
			"username_claim": usernameClaim,
			"claims":         c,
		}).Debug("username claim not found or invalid")
		if err == ErrorClaimNotFound {
			return nil, fmt.Errorf("username claim %s not found", usernameClaim)
		}
		return nil, fmt.Errorf("Unable to get username claim: %s", err)
	}
	review.Status.User.Username = username

	groups, err := c.StringSlice(groupsClaim)
	if err != nil {
		log.WithFields(log.Fields{
			"groups_claim": groupsClaim,
			"claims":       c,
		}).Debug("groups claim not found or invalid")
		if err == ErrorClaimNotFound {
			// If a group claim is required
			if groupsRequired {
				return nil, fmt.Errorf("groups claim %s not found", groupsClaim)
			}
			// Don't error out if groups claim is not present and a group
			// getter is defined. Just log a warning
			log.WithField("groups_claim", groupsClaim).Warn("Groups claim not found...using groups from getter only")
			groups = []string{}
		} else {
			return nil, fmt.Errorf("Unable to get groups claim: %s", err)
		}
	}
	review.Status.User.Groups = groups
	return review, nil
}

func (c claims) hasKey(key string) bool {
	_, ok := c[key]
	return ok
}

// String gets a string value from claims given a key. Returns false if
// the key does not exist
func (c claims) String(key string) (string, error) {
	var resp string
	if !c.hasKey(key) {
		return "", ErrorClaimNotFound
	}
	if v, ok := c[key].(string); ok {
		resp = v
	} else { // Not a string type
		return "", fmt.Errorf("Claim is not a string")
	}
	return resp, nil
}

// StringSlice gets a slice of strings from claims given a key. Returns false if
// the key does not exist
func (c claims) StringSlice(key string) ([]string, error) {
	var resp []string
	var intermediate []interface{}
	if !c.hasKey(key) {
		return nil, ErrorClaimNotFound
	}
	if val, ok := c[key].([]interface{}); ok {
		intermediate = val
	} else {
		return nil, fmt.Errorf("Claim is not a slice")
	}
	// Initialize the slice to the same length as the intermediate slice. This saves
	// some steps with not having to append
	resp = make([]string, len(intermediate))
	// You can't type assert the whole slice as a type, so assert each element to make
	// sure it is a string
	for i := 0; i < len(resp); i++ {
		if strVal, ok := intermediate[i].(string); ok {
			resp[i] = strVal
		} else {
			return nil, fmt.Errorf("Claim is not a slice of strings")
		}
	}
	return resp, nil
}
