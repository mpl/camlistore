/*
Copyright 2014 The Camlistore Authors

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

package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang/oauth2"
)

var (
	projectId = "myimgae"
	cl *http.Client
	clientId = "400003120193-7220c2ljueui97kvoq0mecmeoegerpkm.apps.googleusercontent.com"
	clientSecret = "cfcSVht4YoqDmdawoM49Jlv_"
)


func getScannedFile(key string) error {
//	resp, err := cl.Get("https://myimgae.appspot.com/")
	req, err := http.NewRequest("GET", "https://myimgae.appspot.com/", nil)
	if err != nil {
		return err
	}
	req.Header.Add("X-AppEngine-User-Email", "mathieu.lonjaret@gmail.com")
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Status %v", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return ioutil.WriteFile("/home/mpl/myimgae.html", body, 0700)
}

func transportFromAPIKey2() (*oauth2.Transport, error) {
	conf, err := oauth2.NewConfig(&oauth2.Options{
				Scopes: []string{"https://www.googleapis.com/auth/appengine.admin",
					"https://www.googleapis.com/auth/userinfo.email"},
                ClientID:     clientId,
                ClientSecret: clientSecret,
                RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		},
		"https://accounts.google.com/o/oauth2/auth",
		"https://accounts.google.com/o/oauth2/token")
	if err != nil {
		return nil, err
	}

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
//	url := conf.AuthCodeURL("state", "online", "auto")
	url := conf.AuthCodeURL("state", "offline", "auto")
	fmt.Printf("Visit the URL for the auth dialog: %v\n", url)

	input := bufio.NewReader(os.Stdin)
	line, _, err := input.ReadLine()
	if err != nil {
		log.Fatalf("Failed to read line: %v", err)
	}
	authorizationCode := strings.TrimSpace(string(line))

	return conf.NewTransportWithCode(authorizationCode)
}

func main() {
	tr, err := transportFromAPIKey2()
	if err != nil {
		log.Fatal(err)
	}
	cl = &http.Client{Transport: tr}
	scanBlobKey := "5066549580791808"
	if err := getScannedFile(scanBlobKey); err != nil {
		log.Fatal(err)
	}
}
