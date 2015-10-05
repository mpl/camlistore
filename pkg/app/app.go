/*
Copyright 2014 The Camlistore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package app provides helpers for server applications interacting
// with Camlistore.
package app

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"camlistore.org/pkg/auth"
	"camlistore.org/pkg/client"
	"camlistore.org/pkg/netutil"
)

func BasicAuth() (auth.AuthMode, error) {
	authString := os.Getenv("CAMLI_AUTH")
	if authString == "" {
		return nil, errors.New("CAMLI_AUTH var not set")
	}
	userpass := strings.Split(authString, ":")
	if len(userpass) != 2 {
		return nil, fmt.Errorf("invalid auth string syntax. got %q, want \"username:password\"", authString)
	}
	return auth.NewBasicAuth(userpass[0], userpass[1]), nil
}

// Client returns a client from pkg/client, configured by environment variables
// for applications, and ready to be used to connect to the Camlistore server.
func Client() (*client.Client, error) {
	server := os.Getenv("CAMLI_API_HOST")
	if server == "" {
		return nil, errors.New("CAMLI_API_HOST var not set")
	}
	am, err := BasicAuth()
	if err != nil {
		return nil, err
	}
	cl := client.NewFromParams(server, am)
	cl.SetHTTPClient(&http.Client{
		Transport: cl.TransportForConfig(nil),
	})
	return cl, nil
}

// ListenAddress returns the host:[port] network address, derived from the environment,
// that the application should listen on.
func ListenAddress() (string, error) {
	baseURL := os.Getenv("CAMLI_APP_BACKEND_URL")
	if baseURL == "" {
		return "", errors.New("CAMLI_APP_BACKEND_URL is undefined")
	}
	// TODO(mpl): go back to netutil.HostPort and see if we can't replace it with just url.Parse now that we want to be stricter with these things.
	return netutil.HostPort(baseURL)
}

func BaseURL() (string, error) {
	appHandlerPrefix := os.Getenv("CAMLI_APP_HANDLER_PREFIX")
	if appHandlerPrefix == "" {
		return "", errors.New("CAMLI_APP_HANDLER_PREFIX is undefined")
	}
	apiHost := os.Getenv("CAMLI_API_HOST")
	if apiHost == "" {
		return "", errors.New("CAMLI_API_HOST is undefined")
	}
	return apiHost + strings.TrimPrefix(appHandlerPrefix, "/"), nil
}

func Scheme() (string, error) {
	backendURL := os.Getenv("CAMLI_APP_BACKEND_URL")
	if backendURL == "" {
		return "", errors.New("CAMLI_APP_BACKEND_URL is undefined")
	}
	parsedURL, err := url.Parse(backendURL)
	if err != nil {
		return "", fmt.Errorf("Invalid CAMLI_APP_BACKEND_URL value: %v", err)
	}
	return parsedURL.Scheme, nil
}
