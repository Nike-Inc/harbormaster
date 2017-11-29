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
	"reflect"
	"testing"

	authenticationapi "k8s.io/api/authentication/v1beta1"
)

func TestValidate(t *testing.T) {
	t.Skip("This will be an integration test against a real Okta endpoint")
}

func TestGetClaims(t *testing.T) {
	// TODO(taylor): We need a built token with claims to test this properly and the
	// OIDC package doesn't have a way to easily build a token
	t.Skip("Unimplemented")
}

func TestGetGroups(t *testing.T) {
	// TODO(taylor): This should probably be an integration test because we aren't
	// doing much logic in the function and just checking the cache/calling the
	// groups API
	t.Skip("Unimplemented")
}

func TestNewValidator(t *testing.T) {
	t.Run("no options should return valid default validator", func(t *testing.T) {
		v, err := New()
		if err != nil {
			t.Errorf("Should not have errored: %s", err)
		}
		if v == nil {
			// End the test here if v is nil
			t.Fatal("Got a nil validator")
		}
		if v.clientID != "" || v.groupsClaim != DefaultGroupsClaim || v.usernameClaim != DefaultUsernameClaim {
			t.Errorf("Expected validator to be set to default values but it wasn't. %+v", v)
		}
	})
	t.Run("with options should return valid validator", func(t *testing.T) {
		var cid = "galaxy"
		var group = "holodeck"
		var user = "riker"
		v, err := New(ClientID(cid), GroupsClaim(group), UsernameClaim(user))
		if err != nil {
			t.Errorf("Should not have errored: %s", err)
		}
		if v == nil {
			// End the test here if v is nil
			t.Fatal("Got a nil validator")
		}
		if v.clientID != cid || v.groupsClaim != group || v.usernameClaim != user {
			t.Errorf("Expected validator to be set to configured values but it wasn't: %+v", v)
		}
	})
	t.Run("bad issuer URL should error", func(t *testing.T) {
		v, err := New(IssuerURL("https://127.0.0.1:23453"))
		if err == nil {
			t.Error("Should have errored")
		}
		if v != nil {
			t.Error("Validator should have been nil")
		}
	})
}

var testClaims = claims{
	"email": "picard@ufp.com",
	"groups": []interface{}{
		"starship_enterprise",
		"captains",
	},
	"bad_groups": []interface{}{
		"klingons",
		"romulans",
		1701,
	},
	"bad_email": 1701,
}

func TestReviewFromClaims(t *testing.T) {
	t.Run("valid user and groups claim", func(t *testing.T) {
		var validReview = &authenticationapi.TokenReview{
			Status: authenticationapi.TokenReviewStatus{
				Authenticated: true,
				User: authenticationapi.UserInfo{
					Username: "picard@ufp.com",
					Groups: []string{
						"starship_enterprise",
						"captains",
					},
				},
			},
		}

		review, err := testClaims.ReviewFromClaims("email", "groups", true)
		if err != nil {
			t.Errorf("Error when generating token review: %s", err)
		}
		if review == nil {
			t.Error("Got a nil TokenReview")
		}
		if !reflect.DeepEqual(review, validReview) {
			t.Errorf("Expected TokenReviews to be equal.\nExpected %+v\nGot: %+v", validReview, review)
		}
	})
	t.Run("missing claim without groupsRequired should not error", func(t *testing.T) {
		review, err := testClaims.ReviewFromClaims("email", "no_groups", false)
		if err != nil {
			t.Fatalf("Error when generating token review: %s", err)
		}
		if len(review.Status.User.Groups) != 0 {
			t.Errorf("TokenReview should have an empty groups list. Got a list with length %d", len(review.Status.User.Groups))
		}
	})
	t.Run("invalid claim should error", func(t *testing.T) {
		review, err := testClaims.ReviewFromClaims("bad_email", "groups", true)
		if err == nil {
			t.Error("Expected error with invalid claim")
		}
		if review != nil {
			t.Error("TokenReview should be nil when there is an error")
		}
	})
}

func TestStringClaim(t *testing.T) {
	t.Run("valid claim key should return value", func(t *testing.T) {
		v, err := testClaims.String("email")
		if err != nil {
			t.Errorf("Error getting string: %s", err)
		}
		if v == "" {
			t.Error("Got an empty string instead of value")
		}
	})
	t.Run("non-existent claim key should error", func(t *testing.T) {
		v, err := testClaims.String("warpdrive")
		if err == nil {
			t.Error("Did not get an error")
		}
		if v != "" {
			t.Error("Should be an empty string")
		}
	})
	t.Run("non-string claim should error", func(t *testing.T) {
		v, err := testClaims.String("bad_email")
		if err == nil {
			t.Error("Did not get an error")
		}
		if v != "" {
			t.Error("Should be an empty string")
		}
	})
}

func TestStringSliceClaim(t *testing.T) {
	t.Run("valid claim key should return slice", func(t *testing.T) {
		v, err := testClaims.StringSlice("groups")
		if err != nil {
			t.Errorf("Error getting slice: %s", err)
		}
		if v == nil {
			t.Error("Got a nil slice")
		}
	})
	t.Run("non-existent claim key should error", func(t *testing.T) {
		v, err := testClaims.StringSlice("readyroom")
		if err == nil {
			t.Error("Did not get an error")
		}
		if v != nil {
			t.Error("Should be a nil slice")
		}
	})
	t.Run("non string slice claim should error", func(t *testing.T) {
		v, err := testClaims.StringSlice("email")
		if err == nil {
			t.Error("Did not get an error")
		}
		if v != nil {
			t.Error("Should be a nil slice")
		}
	})
	t.Run("wrong type slice claim should error", func(t *testing.T) {
		v, err := testClaims.StringSlice("bad_groups")
		if err == nil {
			t.Error("Did not get an error")
		}
		if v != nil {
			t.Error("Should be a nil slice")
		}
	})
}
