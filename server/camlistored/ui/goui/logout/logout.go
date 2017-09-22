/*
Copyright 2017 The Camlistore Authors.

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

// Package logout provides a Send function to request logging out from a
// Camlistore's server's web UI.
package logout

import (
	"fmt"
	"net/http"

	"camlistore.org/pkg/auth"

	"honnef.co/go/js/dom"
)

func Send(url string, callback func()) {
	go func() {
		if err := send(url); err != nil {
			dom.GetWindow().Alert(fmt.Sprintf("%v", err))
			return
		}
		callback()
	}()
}

func send(url string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set(auth.LogoutHeader, "true")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("logging out was expecting a 401, but status was %d", resp.StatusCode)
	}
	return nil
}
