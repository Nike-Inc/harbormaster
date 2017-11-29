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

package main

import (
	"io/ioutil"
	"os"
	"testing"
)

var tempCertRaw = `-----BEGIN CERTIFICATE-----
MIIDhDCCAmygAwIBAgIQLsBdzOEkh6k1P7uf5tDoDjANBgkqhkiG9w0BAQsFADBc
MQkwBwYDVQQGEwAxCTAHBgNVBAgTADEJMAcGA1UEBxMAMQkwBwYDVQQREwAxETAP
BgNVBAoTCGJvb3RrdWJlMQkwBwYDVQQLEwAxEDAOBgNVBAMTB2t1YmUtY2EwHhcN
MTcwNzI1MTkyNTE1WhcNMTgwNzI1MTkyNTE1WjBcMQkwBwYDVQQGEwAxCTAHBgNV
BAgTADEJMAcGA1UEBxMAMQkwBwYDVQQREwAxETAPBgNVBAoTCGJvb3RrdWJlMQkw
BwYDVQQLEwAxEDAOBgNVBAMTB2t1YmUtY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCzcaXGF0MWjhW0E3LCW8d8dEvVBA5ownzaBvtq/1nxlNOVofEz
JOA8KePIVK2Nf4TcdE1X27lb+DRviX42Lmz8OR0zCDfhUEtClQIFU0E20xhYzpwE
SH3iiCjQotJRKyF889xcYCnVDwbeZAg5vSone6edCaFHfGrtT+ybhD9GMn13n0T9
cR8pvMgVvEPtiHWtvdTUXL3CTgkW8oYKQIk9C2ABf4cvEZsdNoPmDa/m4STRI776
DxxVzXINY9u+X/+GkLfZeemz2+jh/AOIQn8KLwQFd2R4iBXne3xKZhEQ5SYgiMFH
BsyCVnd1/0+FSzYSmngXXEt4YMy3jp2w2R4BAgMBAAGjQjBAMA4GA1UdDwEB/wQE
AwICpDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSmMMfemJRpFFNYW/gdua0e
St57+jANBgkqhkiG9w0BAQsFAAOCAQEAjk6cKuiYLqskDCfdJmhCz7U0T91CeL8N
9LDfXdcewcsSMg3PsJFEbNWriU9xtkQ5oaQy12XEyWxlV53UzSsAeFsQIAPi81zs
kHure/Ycg9lqV3GUz4ahzarrhd+irAhkHtTQCcy/irfCMR+jltg2hLazr97Y1/yF
4IPkQnP6jTR/s0c5gvmkuMk2ctsW0oe+xls5oglllXLjPvU0++kzZ+8CqK8CRcJw
jsIZMQi+TNG5HdZcDjV2nzh+wCo52kf4ShArgJRdDUeR18CPGJWhO0Efv236Iyv0
2mdECH7jZhL7/5LCSm+xteXoy1soxK3p4AI2VZsL7oRrgoGkj+etvA==
-----END CERTIFICATE-----
`

func createTmpCert(t *testing.T, content string) (string, func()) {
	f, err := ioutil.TempFile(os.TempDir(), "harbormaster-test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(content)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name(), func() {
		os.Remove(f.Name())
	}
}

func TestGenerateTLSConfig(t *testing.T) {
	t.Run("valid cert returns valid config", func(t *testing.T) {
		certPath, cleanup := createTmpCert(t, tempCertRaw)
		defer cleanup()
		conf, err := generateTLSConfig(certPath)
		if err != nil {
			t.Errorf("Did not expect error generating TLS config: %s", err)
		}
		if conf == nil {
			t.Error("Nil config was returned")
		}
	})

	t.Run("invalid cert returns error", func(t *testing.T) {
		certPath, cleanup := createTmpCert(t, "blah blah")
		defer cleanup()
		conf, err := generateTLSConfig(certPath)
		if err == nil {
			t.Error("Expected an error with an invalid certificate")
		}
		if conf != nil {
			t.Error("Returned config should have been nil and wasn't")
		}
	})

	t.Run("invalid file path returns error", func(t *testing.T) {
		conf, err := generateTLSConfig("a/totally/not/valid/path")
		if err == nil {
			t.Error("Expected an error with an invalid path")
		}
		if conf != nil {
			t.Error("Returned config should have been nil and wasn't")
		}
	})
}
