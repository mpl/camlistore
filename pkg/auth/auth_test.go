/*
Copyright 2013 The Camlistore Authors

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

package auth

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

var (
	pkgToken   string
	pkgRoToken string
)

func init() {
	// generate pkg level tokens
	pkgToken = Token()
	pkgRoToken = ROToken()
}

func newString(s string) *string {
	return &s
}

func TestFromConfig(t *testing.T) {
	tests := []struct {
		in string

		want    interface{}
		wanterr interface{}
	}{
		{in: "", wanterr: ErrNoAuth},
		{in: "slkdjflksdjf", wanterr: `Unknown auth type: "slkdjflksdjf"`},
		{in: "none", want: None{}},
		{in: "localhost", want: Localhost{}},
		{in: "userpass:alice:secret", want: &UserPass{Username: "alice", Password: "secret", OrLocalhost: false, VivifyPass: nil}},
		{in: "userpass:alice:secret:+localhost", want: &UserPass{Username: "alice", Password: "secret", OrLocalhost: true, VivifyPass: nil}},
		{in: "userpass:alice:secret:+localhost:vivify=foo", want: &UserPass{Username: "alice", Password: "secret", OrLocalhost: true, VivifyPass: newString("foo")}},
		{in: "userpass:alice:secret:+localhost:vivify=foo:ro=welcome", want: &UserPass{Username: "alice", Password: "secret", OrLocalhost: true, VivifyPass: newString("foo"), ReadOnlyPass: newString("welcome")}},

		{in: "devauth:port3179", want: &DevAuth{Password: "port3179", VivifyPass: newString("viviport3179"), ReadOnlyPass: newString("roport3179")}},
		{in: "basic:alice:secret", want: &UserPass{Username: "alice", Password: "secret", OrLocalhost: false, VivifyPass: nil}},
		{in: "basic:alice:secret:+localhost", wanterr: `invalid basic auth syntax. got "alice:secret:+localhost", want "username:password"`},
		{in: "basic:alice:secret:+vivify=foo", wanterr: `invalid basic auth syntax. got "alice:secret:+vivify=foo", want "username:password"`},
	}
	for _, tt := range tests {
		am, err := FromConfig(tt.in)
		if err != nil || tt.wanterr != nil {
			if fmt.Sprint(err) != fmt.Sprint(tt.wanterr) {
				t.Errorf("FromConfig(%q) = error %v; want %v", tt.in, err, tt.wanterr)
			}
			continue
		}
		if !reflect.DeepEqual(am, tt.want) {
			t.Errorf("FromConfig(%q) = %#v; want %#v", tt.in, am, tt.want)
		}
	}
}

func TestMultiMode(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	(&UserPass{Username: "foo", Password: "bar"}).AddAuthHeader(req)

	modes = []AuthMode{
		&UserPass{
			Username: "foo",
			Password: "baz",
		},
	}

	if Allowed(req, OpAll) {
		t.Fatalf("req should not be allowed")
	}

	AddMode(&UserPass{
		Username: "foo",
		Password: "bar",
	})

	if !Allowed(req, OpAll) {
		t.Fatalf("req should now be allowed")
	}

	SetMode(&UserPass{
		Username: "foo",
		Password: "baz",
	})

	if Allowed(req, OpAll) {
		t.Fatalf("req should not be allowed anymore")
	}
}

func TestReadOnlyMode(t *testing.T) {
	modes = []AuthMode{
		&UserPass{
			Username:     "foo",
			Password:     "bar",
			ReadOnlyPass: newString("baz"),
		},
	}

	// check that pass based auth with read-only password is only allowing OpRead
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	(&UserPass{Username: "foo", Password: "baz"}).AddAuthHeader(req)
	if Allowed(req, OpAll) {
		t.Fatalf("req with userpass should not be allowed for OpAll")
	}
	if !Allowed(req, OpRead) {
		t.Fatalf("req with userpass should be allowed for OpRead")
	}

	// check that token based auth with read-only token is only allowing OpRead
	req, err = http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	(&tokenAuth{token: pkgRoToken}).AddAuthHeader(req)
	if Allowed(req, OpAll) {
		t.Fatalf("req with token should not be allowed for OpAll")
	}
	if !Allowed(req, OpRead) {
		t.Fatalf("req with token should be allowed for OpRead")
	}

	// check that full rights pass based password gets OpAll
	req, err = http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	(&UserPass{Username: "foo", Password: "bar"}).AddAuthHeader(req)
	if !Allowed(req, OpAll) {
		t.Fatalf("req with userpass should be allowed for OpAll")
	}

	// check that full rights token gets OpAll
	req, err = http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	(&tokenAuth{token: pkgToken}).AddAuthHeader(req)
	if !Allowed(req, OpAll) {
		t.Fatalf("req with token should be allowed for OpAll")
	}
}

func TestEmptyPasswords(t *testing.T) {
	tests := []struct {
		config           string
		providedPassword string

		allowed bool
	}{
		{config: "foo:", providedPassword: "", allowed: true},
		{config: "foo:", providedPassword: "bar", allowed: false},
		{config: "foo:bar", providedPassword: "", allowed: false},
		{config: "foo:bar", providedPassword: "bar", allowed: true},
		{config: "foo:bar:vivify=", providedPassword: "", allowed: true},
		{config: "foo:bar:vivify=", providedPassword: "notbar", allowed: false},
		{config: "foo:bar:vivify=otherbar", providedPassword: "", allowed: false},
		{config: "foo:bar:vivify=otherbar", providedPassword: "notbar", allowed: false},
		{config: "foo:bar:vivify=otherbar", providedPassword: "bar", allowed: true},
		{config: "foo:bar:vivify=otherbar", providedPassword: "otherbar", allowed: true},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatal(err)
		}
		(&UserPass{Username: "foo", Password: test.providedPassword}).AddAuthHeader(req)

		auth, err := newUserPassAuth(test.config)
		if err != nil {
			t.Errorf(err.Error())
			continue
		}
		SetMode(auth)

		if Allowed(req, OpVivify) != test.allowed {
			t.Errorf("Allowed(req, OpVivify) = %#v; want %#v (config: %q, providedPassword: %q)",
				Allowed(req, OpVivify), test.allowed, test.config, test.providedPassword)
		}
	}
}
