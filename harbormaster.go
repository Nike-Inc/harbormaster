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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/Nike-Inc/harbormaster/internal/pkg/handler"
	"github.com/Nike-Inc/harbormaster/internal/pkg/validator"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var levelMapping = map[string]log.Level{
	"DEBUG": log.DebugLevel,
	"INFO":  log.InfoLevel,
	"WARN":  log.WarnLevel,
	"ERROR": log.ErrorLevel,
}

const (
	portFlag              = "port"
	healthPortFlag        = "health-port"
	logLevelFlag          = "log-level"
	caCertFlag            = "ca-cert"
	certFlag              = "cert"
	keyFlag               = "key"
	clientIDFlag          = "client-id"
	issuerURLFlag         = "issuer-url"
	usernameClaimFlag     = "username-claim"
	groupClaimFlag        = "group-claim"
	memoryFlag            = "cache-max-memory"
	cacheExpiryFlag       = "cache-expiry"
	graphClientIDFlag     = "graph-client-id"
	graphClientSecretFlag = "graph-client-secret"
	graphTenantNameFlag   = "graph-tenant-name"
)

var harbormasterCmd = &cobra.Command{
	Use:   "harbormaster",
	Short: "A webhook handler for validating JWT",
	Long: `A webhook handler for validating JWT tokens sent to Kubernetes. In addition to
validating the token, it can also add data to the user information returned
to Kubernetes. This additional user information is cached to decrease the amount
of trips out to active directory. The cache duration and size are configurable.`,
	RunE: startHarbormaster,
}

func init() {
	viper.SetEnvPrefix("harbormaster")
	viper.AutomaticEnv()
	// This normalizes "-" to an underscore in env names.
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	flags := harbormasterCmd.Flags()
	flags.IntP(portFlag, "p", 9000, "port harbormaster should listen on. [HARBORMASTER_PORT]")
	flags.IntP(memoryFlag, "m", validator.DefaultMaxCacheMemory, "amount of memory (in MB) to cap the cache at [HARBORMASTER_CACHE_MAX_MEMORY]")
	flags.DurationP(cacheExpiryFlag, "e", validator.DefaultCacheDuration, "how long before a cache entry is considered invalid [HARBORMASTER_CACHE_EXPIRY]")
	flags.Int(healthPortFlag, 8000, "port to listen on for health checks. [HARBORMASTER_HEALTH_PORT]")
	flags.StringP(logLevelFlag, "v", "WARN", "log level to use. Must be one of: 'DEBUG', 'INFO', 'WARN', or 'ERROR'. [HARBORMASTER_LOG_LEVEL]")
	flags.StringP(caCertFlag, "r", "/usr/share/harbormaster/ca.pem", "ca certificate to use for root trust. This is required. [HARBORMASTER_CA_CERT]")
	flags.StringP(certFlag, "c", "/usr/share/harbormaster/harbormaster.pem", "certificate to use for https. This is required. [HARBORMASTER_CERT]")
	flags.StringP(keyFlag, "k", "/usr/share/harbormaster/harbormaster.key", "keyfile for the certificate. This is required. [HARBORMASTER_KEY]")
	flags.StringP(clientIDFlag, "i", "", "OIDC provider client ID. [HARBORMASTER_CLIENT_ID]")
	flags.StringP(issuerURLFlag, "u", validator.DefaultIssuerURL, "OIDC token issuer URL. [HARBORMASTER_ISSUER_URL]")
	flags.StringP(usernameClaimFlag, "n", validator.DefaultUsernameClaim, "claim to use as the username [HARBORMASTER_USERNAME_CLAIM]")
	flags.StringP(groupClaimFlag, "g", validator.DefaultGroupsClaim, "claim to use for user's groups [HARBORMASTER_GROUP_CLAIM]")
	flags.String(graphClientIDFlag, "", "MS Graph application client ID to use [HARBORMASTER_GRAPH_CLIENT_ID]")
	flags.String(graphClientSecretFlag, "", "MS Graph application client secret to use [HARBORMASTER_GRAPH_CLIENT_SECRET]")
	flags.String(graphTenantNameFlag, "", "MS Graph application tenant name to use (generally <company>.onmicrosoft.com) [HARBORMASTER_GRAPH_TENANT_NAME]")
	viper.BindPFlags(flags)
}

// Given a location of a PEM encoded certificate and keyfile path, attempt to load
// the certificate and return a TLS config suitable for use with a server
func generateTLSConfig(rootCA string) (*tls.Config, error) {
	content, err := ioutil.ReadFile(rootCA)
	if err != nil {
		return nil, fmt.Errorf("Error reading root CA file: %s", err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(content); !ok {
		return nil, fmt.Errorf("Unable to parse ca file as a PEM encoded certificate")
	}
	conf := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
		ClientCAs:  pool,
	}
	conf.BuildNameToCertificate()
	return conf, nil
}

func startHarbormaster(cmd *cobra.Command, args []string) error {
	if l, ok := levelMapping[viper.GetString(logLevelFlag)]; ok {
		log.SetLevel(l)
		f := &log.TextFormatter{
			FullTimestamp: true,
		}
		log.SetFormatter(f)
	} else {
		return fmt.Errorf("Invalid log level. Must be one of: 'DEBUG', 'INFO', 'WARN', or 'ERROR'")
	}

	if viper.GetString(clientIDFlag) == "" {
		return fmt.Errorf("--%s should be specified", clientIDFlag)
	}
	// Initialize the validator with all necessary information
	log.Debug("Setting up validator")
	var opts = []validator.Option{
		validator.ClientID(viper.GetString(clientIDFlag)),
		validator.IssuerURL(viper.GetString(issuerURLFlag)),
		validator.UsernameClaim(viper.GetString(usernameClaimFlag)),
		validator.GroupsClaim(viper.GetString(groupClaimFlag)),
		validator.CacheSize(viper.GetInt(memoryFlag)),
		validator.CacheExpiry(viper.GetDuration(cacheExpiryFlag)),
	}
	if viper.GetString(graphClientIDFlag) == "" || viper.GetString(graphClientSecretFlag) == "" || viper.GetString(graphTenantNameFlag) == "" {
		log.Warn("Graph client ID, client secret, or tenent name not set. Skipping group getter")
	} else {
		opts = append(opts, validator.GraphGetter(viper.GetString(graphClientIDFlag), viper.GetString(graphClientSecretFlag), viper.GetString(graphTenantNameFlag)))
	}
	v, err := validator.New(opts...)
	if err != nil {
		return err
	}
	log.Debug("Setting up OIDC handler")
	th := handler.NewTokenHandler(v)

	// Routing for webhook
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/validate", th.ValidateTokenReview)

	// Generate the TLS configuration and set up the server
	listenAddr := fmt.Sprintf(":%d", viper.GetInt(portFlag))
	log.WithField("ca-path", viper.GetString(caCertFlag)).Debug("Generating TLS config with ca certificate")
	tlsConfig, err := generateTLSConfig(viper.GetString(caCertFlag))
	if err != nil {
		return err
	}
	s := http.Server{
		Addr:      listenAddr,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	// Start the webhook server
	log.WithFields(log.Fields{
		"cert-path": viper.GetString(certFlag),
		"key-path":  viper.GetString(keyFlag),
		"address":   listenAddr,
	}).Info("Starting server")
	// TODO(taylor): Error handling on server startup
	go s.ListenAndServeTLS(viper.GetString(certFlag), viper.GetString(keyFlag))
	// Health check endpoint on non https
	var healthListenAddr = fmt.Sprintf(":%d", viper.GetInt(healthPortFlag))

	// Configure the health routing and start the health check server
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", handler.HealthCheck)
	log.WithField("address", healthListenAddr).Info("Starting health check endpoint")
	http.ListenAndServe(healthListenAddr, healthMux)
	return nil
}

func main() {
	if err := harbormasterCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
