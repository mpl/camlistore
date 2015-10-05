// +build nope

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
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"camlistore.org/pkg/client"
	"camlistore.org/pkg/osutil"
	"camlistore.org/pkg/schema"
	"camlistore.org/pkg/schema/nodeattr"

	"github.com/mpl/scancabimport/third_party/github.com/golang/oauth2"
	"github.com/mpl/scancabimport/third_party/google.golang.org/cloud/datastore"
)

var (
	verbose = flag.Bool("v", false, "verbose")
	skipGAE = flag.Bool("skipgae", false, "do not refetch from GAE, reuse metadata stored in .json in previous run")
)

const (
	projectId = "scancabcamli"

	tokenCacheFile = "tokencache.json"
	scansDir       = "scans"             // where the scanned files will be stored
	mediaObjects   = "mediaObjects.json" // scans metadata
	documents      = "documents.json"    // documents metadata
)

var (
	ds *datastore.Dataset
	cl *http.Client
)

// UserInfo represents the metadata associated with the Google User
// currently logged-in to the app
type UserInfo struct {
	// User stores the email address of the currently logged-in user
	// this is used as the primary key
	User string

	// MediaObjects is a count of the MediaObjects currently associated with this user
	MediaObjects int64

	// UploadPassword is a plain-text string that protects the scan upload API
	UploadPassword string
}

// MediaObject represents the metadata associated with each individual uploaded scan
type MediaObject struct {
	// Owner is the key of the UserInfo of the user that uploaded the file
	Owner *datastore.Key `json:"-"`

	// Id is the entity ID of the key associated with this MediaObject struct
	// Not imported in Camlistore, but needed to fetch the actual scan.
	Id int64 `datastore:"-"`

	// Creation is the time when this the scan was uploaded.
	Creation time.Time

	// Filename is the name of the file when it was uploaded
	// Needed for upload, but no need to set it on the scan permanode, as it is set on the file blob.
	Filename string

	// Document is the key of the associated Document struct.
	// A Document has many MediaObjects. When newly uploaded,
	// a MediaObject is not associated with a Document.
	// Not imported in Camlistore, but used to get all the documents.
	Document *datastore.Key `json:"-"`
}

// Document is a structure that groups scans into a logical unit.
// A letter (Stored as a document) could have several pages
// (each is a MediaObject), for example.
type Document struct {
	// Owner is the key of the UserInfo of the user that created the Document
	Owner *datastore.Key

	// Pages are the keys of each Media Object that contitute this Document.
	// Not imported as such in camli, but used to build the Document->scans relation.
	Pages []*datastore.Key

	// TODO(mpl): Preview?

	// Id is the entity ID of the key associated with this Document struct
	// Not imported in Camlistore, and not needed, but kept in json for easier debugging.
	Id int64 `datastore:"-"`

	// DocDate is the user-nominated date associated with this document. It can
	// store any date the user likes but is intended to be when the document was
	// received, or, perhaps, written or sent.
	// Stored in camli as nodeattr.DatePublished.
	DocDate time.Time

	// Creation is the date the Document struct was created
	// Stored in camli as nodeattr.DateCreated.
	Creation time.Time

	// Title is the user-nominated title of the document
	Title string

	// Description is the user-nominated description of the document
	Description string

	// Tags is the slice of zero or more tags associated with the document by the user
	Tags []string

	// PhysicalLocation is the user-nominated description of the location
	// of the physical document of which the MediaObjects associated with this
	// Document are scans
	// TODO(mpl): add a nodeattr?
	PhysicalLocation string

	// DueDate is the user-nominated date that the document is "due". The
	// meaning of what "due" means in relation to each particular document
	// is up to the user
	// TODO(mpl): add a nodeattr?
	DueDate time.Time

	Starred bool
}

const (
	// TODO(mpl): figure out how high these can be cranked up.
	scansRequestLimit = 5
	docsRequestLimit  = 5
)

func getScans() ([]*MediaObject, error) {
	var scans []*MediaObject
	query := ds.NewQuery("MediaObject")
	query = query.Limit(scansRequestLimit)
	for {
		sc := make([]*MediaObject, scansRequestLimit)
		keys, next, err := ds.RunQuery(query, sc)
		if err != nil {
			return nil, err
		}
		// get the key id and store it in the media object because we'll need it
		// to fetch the corresponding file from the blobstore later.
		for i, obj := range sc {
			if obj == nil {
				break
			}
			obj.Id = keys[i].ID()
		}
		scans = append(scans, sc...)
		if next == nil {
			break
		}
		query = next
	}
	end := -1
	for k, v := range scans {
		if v == nil {
			end = k
			break
		}
	}
	if end > 0 {
		scans = scans[:end]
	}
	return scans, nil
}

func getScannedFile(resourceId, filename string) error {
	if resourceId == "" {
		log.Printf("WARNING: Not fetching scan because empty resourceId")
		return nil
	}
	if resourceId == "" {
		log.Printf("WARNING: Not fetching scan because empty filename")
		return nil
	}
	filePath := filepath.Join(scansDir, filename)
	if _, err := os.Stat(filePath); err == nil {
		log.Printf("%s already exists, skipping download.", filePath)
		return nil
	}
	resp, err := cl.Get("https://" + projectId + ".appspot.com/resource/" + resourceId + "/" + filename)
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
	return ioutil.WriteFile(filePath, body, 0700)
}

func cacheToken(tok *oauth2.Token) error {
	file, err := os.OpenFile(tokenCacheFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			panic(err)
		}
	}()
	if err := json.NewEncoder(file).Encode(tok); err != nil {
		return err
	}
	return nil
}

func cachedToken() (*oauth2.Token, error) {
	file, err := os.Open(tokenCacheFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	tok := &oauth2.Token{}
	if err := json.NewDecoder(file).Decode(tok); err != nil {
		return nil, err
	}
	return tok, nil
}

func transportFromAPIKey() (*oauth2.Transport, error) {
	// APIkey credentials. used to auth against both the app itself, and the datastore API.
	clientId := os.Getenv("CLIENTID")
	if clientId == "" {
		return nil, fmt.Errorf("CLIENTID not set")
	}
	clientSecret := os.Getenv("CLIENTSECRET")
	if clientSecret == "" {
		return nil, fmt.Errorf("CLIENTSECRET not set")
	}
	conf, err := oauth2.NewConfig(&oauth2.Options{
		Scopes: []string{"https://www.googleapis.com/auth/appengine.admin", // TODO(mpl): maybe not needed?
			"https://www.googleapis.com/auth/datastore",
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

	token, err := cachedToken()
	if err == nil {
		tr := conf.NewTransport()
		tr.SetToken(token)
		return tr, nil
	}

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL("state", "online", "auto")
	// url := conf.AuthCodeURL("state", "offline", "auto")
	fmt.Printf("Visit the URL for the auth dialog:\n%v\n", url)
	fmt.Println("And enter the authorization string displayed in your browser:")

	input := bufio.NewReader(os.Stdin)
	line, _, err := input.ReadLine()
	if err != nil {
		log.Fatalf("Failed to read line: %v", err)
	}
	authorizationCode := strings.TrimSpace(string(line))
	tr, err := conf.NewTransportWithCode(authorizationCode)
	if err != nil {
		return nil, err
	}
	if err := cacheToken(tr.Token()); err != nil {
		return nil, err
	}
	return tr, nil
}

func writeObjects(scans []*MediaObject, docs map[int64]*Document) error {
	f, err := os.OpenFile(mediaObjects, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(scans); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	docsArray := make([]*Document, 0, len(docs))
	for _, v := range docs {
		if v == nil {
			panic("a nil doc was not stripped off the map")
		}
		docsArray = append(docsArray, v)
	}
	f, err = os.OpenFile(documents, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(docsArray); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

func getUsers(scans []*MediaObject) (map[int64]*UserInfo, error) {
	users := make(map[int64]*UserInfo)
	for _, v := range scans {
		if v == nil {
			continue
		}
		if *verbose {
			fmt.Printf("%v\n", v)
		}
		if v.Owner != nil {
			userId := v.Owner.ID()
			if _, ok := users[userId]; !ok {
				userInfo := &UserInfo{}
				if err := ds.Get(v.Owner, userInfo); err != nil {
					return nil, err
				}
				users[userId] = userInfo
				if *verbose {
					fmt.Printf("Owner: %v\n", userInfo)
				}
			}
		}
	}
	return users, nil
}

func getDocuments(scans []*MediaObject) (map[int64]*Document, error) {
	docs := make(map[int64]*Document)
	for _, v := range scans {
		//		if !v.LacksDocument && v.Document != nil {
		if v.Document != nil {
			docId := v.Document.ID()
			if _, ok := docs[docId]; ok {
				if *verbose {
					fmt.Printf("Document cache hit: %d\n", docId)
				}
				continue
			}
			document := &Document{}
			if err := ds.Get(v.Document, document); err != nil {
				return nil, err
			}
			document.Id = docId
			docs[docId] = document
			if *verbose {
				fmt.Printf("Document: %v\n", document)
			}
		}
	}
	return docs, nil
}

func main() {
	flag.Parse()

	if err := os.MkdirAll(scansDir, 0700); err != nil {
		log.Fatal(err)
	}

	tr, err := transportFromAPIKey()
	if err != nil {
		log.Fatal(err)
	}
	cl = &http.Client{Transport: tr}

	ds, err = datastore.NewDatasetWithTransport(projectId, tr)
	if err != nil {
		log.Fatal(err)
	}

	if !*skipGAE {
		scans, err := getScans()
		if err != nil {
			log.Fatal(err)
		}

		users, err := getUsers(scans)
		if err != nil {
			log.Fatal(err)
		}
		_ = users
		for _, v := range scans {
			if v == nil {
				continue
			}
			if err := getScannedFile(fmt.Sprintf("%d", v.Id), v.Filename); err != nil {
				log.Fatal(err)
			}
		}
		docs, err := getDocuments(scans)
		if err != nil {
			log.Fatal(err)
		}

		if err := writeObjects(scans, docs); err != nil {
			log.Fatal(err)
		}
	}

	scansBytes, err := ioutil.ReadFile(mediaObjects)
	if err != nil {
		log.Fatal(err)
	}
	docsBytes, err := ioutil.ReadFile(documents)
	if err != nil {
		log.Fatal(err)
	}
	var scans []*MediaObject
	if err := json.Unmarshal(scansBytes, &scans); err != nil {
		log.Fatalf("decoding scans: %v", err)
	}
	var docs []*Document
	if err := json.Unmarshal(docsBytes, &docs); err != nil {
		log.Fatalf("decoding documents: %v", err)
	}

	for _, v := range scans {
		fmt.Printf("%v\n", v)
	}
	for _, v := range docs {
		fmt.Printf("%v\n", v)
	}

	if err := uploadObjects(scansToMap(scans), docs); err != nil {
		log.Fatal(err)
	}
}

type scanAttrs map[string]string

func scansToMap(mo []*MediaObject) map[int64]scanAttrs {
	m := make(map[int64]scanAttrs, len(mo))
	for _, v := range mo {
		m[v.Id] = v.attrs()
	}
	return m
}

func (mo *MediaObject) attrs() scanAttrs {
	// TODO(mpl): owner?
	attrs := make(map[string]string)
	ctime := mo.Creation.Format(time.RFC3339)
	attrs[nodeattr.DateCreated] = ctime
	attrs["filename"] = mo.Filename
	return attrs
}

func (doc *Document) attrs() map[string]string {
	attrs := make(map[string]string)
	docDate := doc.DocDate.Format(time.RFC3339)
	ctime := doc.Creation.Format(time.RFC3339)
	dueDate := doc.DueDate.Format(time.RFC3339)
	attrs[nodeattr.DatePublished] = docDate
	attrs["creationTime"] = ctime
	attrs["title"] = doc.Title
	attrs[nodeattr.Description] = doc.Description
	attrs["tags"] = strings.Join(doc.Tags, ",")
	attrs["physicalLocation"] = doc.PhysicalLocation
	attrs["dueDate"] = dueDate
	attrs["starred"] = fmt.Sprintf("%v", doc.Starred)
	return attrs
}

func uploadObjects(scans map[int64]scanAttrs, docs []*Document) error {
	if err := os.Setenv("CAMLI_DISABLE_CLIENT_CONFIG_FILE", "true"); err != nil {
		return err
	}
	if err := os.Setenv("CAMLI_SERVER", "http://localhost:3179"); err != nil {
		return err
	}
	osutil.AddSecretRingFlag()
	if err := os.Setenv("CAMLI_SECRET_RING", "/home/mpl/camlistore.org/pkg/jsonsign/testdata/test-secring.gpg"); err != nil {
		return err
	}
	if err := os.Setenv("CAMLI_KEYID", "26F5ABDA"); err != nil {
		return err
	}
	camcl := client.NewOrFail()
	// first pass: upload scans and their attrs
	for scanId, scanAttrs := range scans {
		pr, err := camcl.UploadNewPermanode()
		if err != nil {
			return fmt.Errorf("could not create permanode for scan %v: %v", scanId, err)
		}

		for attr, val := range scanAttrs {
			if attr == "filename" {
				continue
			}
			if _, err := camcl.UploadAndSignBlob(schema.NewSetAttributeClaim(pr.BlobRef, attr, val)); err != nil {
				return fmt.Errorf("could not set (%v, %v) for scan permanode %v: %v", attr, val, pr, err)
			}
		}

		// upload actual scan file
		filename := scanAttrs["filename"]
		f, err := os.Open(filepath.Join(scansDir, filename))
		if err != nil {
			return err
		}
		fileRef, err := schema.WriteFileFromReader(camcl, filename, f)
		f.Close()
		if err != nil {
			return fmt.Errorf("could not upload scan %v: %v", filename, err)
		}
		// and set it as camliContent
		if _, err := camcl.UploadAndSignBlob(schema.NewSetAttributeClaim(pr.BlobRef, "camliContent", fileRef.String())); err != nil {
			return fmt.Errorf("could not set %v as camliContent of %v: %v", filename, pr.BlobRef, err)
		}

		// keeping track of the permanode, so we have them handy when doing the relation with the doc
		scanAttrs["permanode"] = pr.BlobRef.String()
		scans[scanId] = scanAttrs
	}

	// second pass: upload docs
	for _, doc := range docs {
		pr, err := camcl.UploadNewPermanode()
		if err != nil {
			return fmt.Errorf("could not create permanode for doc %v: %v", doc.Id, err)
		}

		for attr, val := range doc.attrs() {
			if attr == "tags" {
				for _, tag := range strings.Split(val, ",") {
					if _, err := camcl.UploadAndSignBlob(
						schema.NewAddAttributeClaim(pr.BlobRef, "tag", tag)); err != nil {
						return fmt.Errorf("could not set (%v, %v) for document permanode %v: %v", "tag", tag, pr, err)
					}
				}
				continue
			}
			if _, err := camcl.UploadAndSignBlob(schema.NewSetAttributeClaim(pr.BlobRef, attr, val)); err != nil {
				return fmt.Errorf("could not set (%v, %v) for document permanode %v: %v", attr, val, pr, err)
			}
		}

		// third pass: pages of each document
		page := 1
		for _, pageKey := range doc.Pages {
			pageId := pageKey.ID()
			pn, ok := scans[pageId]["permanode"]
			if !ok {
				return fmt.Errorf("could not find permanode for scan %v", pageId)
			}
			camliPath := fmt.Sprintf("camliPath:%d", page)
			if _, err := camcl.UploadAndSignBlob(
				schema.NewSetAttributeClaim(pr.BlobRef, camliPath, pn)); err != nil {
				return fmt.Errorf("could not set (%v, %v) for document permanode %v: %v", camliPath, pn, pr, err)
			}
			page++
		}
	}
	return nil

}
