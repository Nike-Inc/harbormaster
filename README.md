# Harbormaster
Harbormaster is a [webhook handler](https://kubernetes.io/docs/admin/authentication/#webhook-token-authentication)
for validating JWT tokens sent to the Kubernetes API. This gives the flexibility
to add extra information to the user object for Kubernetes.

[![GoDoc](https://godoc.org/github.com/Nike-Inc/harbormaster?status.svg)](https://godoc.org/github.com/Nike-Inc/harbormaster)
[![Go Report Card](https://goreportcard.com/badge/github.com/Nike-Inc/harbormaster)](https://goreportcard.com/report/github.com/Nike-Inc/harbormaster)

## Usage
Harbormaster can be configured using command line flags or environment variables.
A list of those is below:

```
Flags:
  -r, --ca-cert string               ca certificate to use for root trust. This is required. [HARBORMASTER_CA_CERT] (default "/usr/share/harbormaster/ca.pem")
  -e, --cache-expiry duration        how long before a cache entry is considered invalid [HARBORMASTER_CACHE_EXPIRY] (default 1h0m0s)
  -m, --cache-max-memory int         amount of memory (in MB) to cap the cache at [HARBORMASTER_CACHE_MAX_MEMORY] (default 1024)
  -c, --cert string                  certificate to use for https. This is required. [HARBORMASTER_CERT] (default "/usr/share/harbormaster/harbormaster.pem")
  -i, --client-id string             OIDC provider client ID. [HARBORMASTER_CLIENT_ID]
      --graph-client-id string       MS Graph application client ID to use [HARBORMASTER_GRAPH_CLIENT_ID]
      --graph-client-secret string   MS Graph application client secret to use [HARBORMASTER_GRAPH_CLIENT_SECRET]
      --graph-tenant-name string     MS Graph application tenant name to use (generally <company>.onmicrosoft.com) [HARBORMASTER_GRAPH_TENANT_NAME]
  -g, --group-claim string           claim to use for user's groups [HARBORMASTER_GROUP_CLAIM] (default "groups")
      --health-port int              port to listen on for health checks. [HARBORMASTER_HEALTH_PORT] (default 8000)
  -h, --help                         help for harbormaster
  -u, --issuer-url string            OIDC token issuer URL. [HARBORMASTER_ISSUER_URL] (default "https://example.oktapreview.com")
  -k, --key string                   keyfile for the certificate. This is required. [HARBORMASTER_KEY] (default "/usr/share/harbormaster/harbormaster.key")
  -v, --log-level string             log level to use. Must be one of: 'DEBUG', 'INFO', 'WARN', or 'ERROR'. [HARBORMASTER_LOG_LEVEL] (default "WARN")
  -p, --port int                     port harbormaster should listen on. [HARBORMASTER_PORT] (default 9000)
  -n, --username-claim string        claim to use as the username [HARBORMASTER_USERNAME_CLAIM] (default "email")
```

Harbormaster relies on TLS authentication to validate the connection. We recommend
using the same CA that is used for the Kubernetes API server, and, if possible,
the same API server key for setting up HTTPS. HTTPS **is required** for the webhook
and we have no plans to support authentication webhooks without encryption.

### Group getters
Harbormaster supports getting additional user groups from other sources. Currently,
only one source is implemented. However, additional sources can be added by
implementing the `groups.Getter` interface. The groups sent back to Kubernetes
will be any groups contained in the JWT combined with any groups from a group getter.
If no group getter configuration is specified, Harbormaster will only use the 
groups from the JWT.

For performance, Harbormaster caches group lookups. The amount of time a cache 
entry is valid can be adjusted with a command line flag.

#### Microsoft Graph
You can optionally specify a Microsoft Graph API [client ID, secret](https://developer.microsoft.com/en-us/graph/docs/concepts/auth_v2_service),
and tenant name. If you specify these flags or environment variables, Harbormaster
will fetch groups from MS Graph.

### Caveats
The username claim specifies which username is used when querying the MS graph API. 
So if it isn't an email address, the lookup in the MS Graph API may fail.

### Docker images
We build Docker images for Harbormaster that are hosted on Docker Hub.
Every commit to master pushes a new build tagged as `canary` for those who want
to use the bleeding edge. Otherwise, the version of Harbormaster will be used to tag the image.

## Development
Development should be fairly straightforward for anyone who has built Go-based project. There are 
only 2 dependencies: a valid Go installation and the new [`dep` tool](https://github.com/golang/dep#setup) 
(that will soon be added into the main Go toolchain). Once you have those installed, 
you will need to clone this project into the proper place in your `GOPATH`:

```bash
mkdir -p $GOPATH/src/github.com/Nike-Inc
cd $GOPATH/src/github.com/Nike-Inc
git clone git@github.com:Nike-Inc/harbormaster.git
cd harbormaster
```

To get started, run `make bootstrap` to install project dependencies. Once that
is done, you can run `make test` to run the package tests and `make build` to
build a local binary at `./harbormaster`.

### How it works
Most of the functionality is broken out into different internal packages that
can only be used by Harbormaster. There are also a few external packages. The
internal packages are located at `./internal/pkg` and a description of each follows.

|   Package   |                                               Purpose                                               |
| ----------- | --------------------------------------------------------------------------------------------------- |
| `handler`   | Contains http handler functions and related helpers to handle and decode the `TokenReview` requests |
| `validator` | Contains all necessary functions for validating and caching token data                              |

The external packages currently consist only of code related to group getters:

| Package  |                                             Purpose                                             |
| -------- | ----------------------------------------------------------------------------------------------- |
| `graph`  | A package for logging into and accessing user group information from the MS Graph API           |
| `groups` | A simple package containing the `Getter` interface that must be implemented by any group getter |

The workflow can be a bit confusing at first glance. It is broken down below
for easy reference:

1. Harbormaster receives a JSON encoded `TokenReview` object from the API server
1. The `TokenReview` is deserialized into a native Kubernetes `TokenReview` object
1. The token is retrieved from the object and validated using an OIDC library
1. A map of claims is retrieved from the token for use in constructing the response to the API server
1. If a group getter is configured, these additional steps occur
    1. The validator checks if a list of user groups associated with the username exists
    1. If the cache entry exists, it uses those groups. Otherwise it uses the getter to fetch a group list and caches it
1. Using the username and group list, a new `TokenReview` object is created and serialized to JSON before sending back to the API server

### Releases and Docker images
To build binaries for a release, run the `make release` command. This will 
build binaries for Windows, Linux, and MacOS in parallel and tag them with a
version using `git describe --always --tags`. You can also manually specify a
version using the `VERSION` environment variable.

If you wish to build a docker image, you can use `make image` to build one. Essentially,
all that is happening is a `make release` and then it wraps those binaries in a
Docker image. Once again, `VERSION` will be used for tagging the image.

To push an image, run `make image-push`. You must be logged in to Docker Hub in
order to run this step. If you used `VERSION` in any of the previous steps, you
will need to set it here as well. 

## Roadmap
We keep track of outstanding issues and enhancement in the [issues page](https://github.com/Nike-Inc/harbormaster/issues).
You can follow along with existing issues or request new features there. However,
the first priorities on our list are below:

- Integration Tests
- Performance optimizations
- Distributed cache instead of a local cache

## Maintainers

- [Taylor Thomas](https://github.com/thomastaylor312)
- [Roger Ignazio](https://github.com/rji)
- [Jay Wallace](https://github.com/mootpt)
