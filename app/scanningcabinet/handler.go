/*
Copyright 2015 The Camlistore Authors.
// TODO(mpl): should we simply add Patrick Borgeest to the list of AUTHORS ? (barring any CLA problem).
Copyright 2013 Patrick Borgeest

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
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"camlistore.org/pkg/app"
	"camlistore.org/pkg/auth"
	"camlistore.org/pkg/blob"
	"camlistore.org/pkg/client"
	"camlistore.org/pkg/constants"
	"camlistore.org/pkg/httputil"
	"camlistore.org/pkg/magic"
	"camlistore.org/pkg/search"
	camliserver "camlistore.org/pkg/server"
	"camlistore.org/pkg/syncutil"
)

const (
	maxScan = 50 // number of scans fetched/displayed. arbitrary.
	maxDue  = 30 // number of due documents fetched

	scanNodeType     = "scanningcabinet:scan"
	documentNodeType = "scanningcabinet:document"
)

var (
	rootTemplate = template.Must(template.New("root").Parse(rootHTML))
	docTemplate  = template.Must(template.New("doc").Parse(docHTML))

	resourcePattern *regexp.Regexp = regexp.MustCompile(`^/resource/(` + blob.Pattern + `)$`)
)

// config is used to unmarshal the application configuration JSON
// that we get from Camlistore when we request it at $CAMLI_APP_CONFIG_URL.
type extraConfig struct {
	Auth string `json:"auth,omitempty"` // userpass:username:password
}

func appConfig() (*extraConfig, error) {
	configURL := os.Getenv("CAMLI_APP_CONFIG_URL")
	if configURL == "" {
		log.Printf("CAMLI_APP_CONFIG_URL not defined, the app will run without any auth")
		return nil, nil
	}
	cl, err := app.Client()
	if err != nil {
		return nil, fmt.Errorf("could not get a client to fetch extra config: %v", err)
	}
	conf := &extraConfig{}
	if err := cl.GetJSON(configURL, conf); err != nil {
		return nil, fmt.Errorf("could not get app extra config at %v: %v", configURL, err)
	}
	return conf, nil
}

type handler struct {
	baseURL string
	scheme  string
	host    string
	mux     *http.ServeMux
	sh      search.QueryDescriber
	// TODO(mpl): later we should have an uploader interface instead. implemented by *client.Client like sh, but they wouldn't have to be the same in theory. right now they actually are.
	cl *client.Client
	ih *camliserver.ImageHandler

	signer blob.Ref
	server string
}

func newHandler() (http.Handler, error) {
	baseURL, err := app.BaseURL()
	if err != nil {
		return nil, err
	}

	cl, err := app.Client()
	if err != nil {
		return nil, fmt.Errorf("could not initialize a client: %v", err)
	}
	host, err := app.ListenAddress()
	if err != nil {
		return nil, err
	}
	scheme, err := app.Scheme()
	if err != nil {
		return nil, err
	}
	h := &handler{
		baseURL: baseURL,
		sh:      cl,
		cl:      cl,
		scheme:  scheme,
		host:    host,
	}

	mux := http.NewServeMux()
	// TODO(mpl): is there a case where anyone would ever need an URL path prefix ?
	mux.HandleFunc("/", h.handleRoot)
	mux.HandleFunc("/uploadurl", h.handleUploadURL)
	mux.HandleFunc("/upload", h.handleUpload)
	mux.HandleFunc("/resource/", h.handleResource)
	mux.HandleFunc("/makedoc", h.handleMakedoc)
	mux.HandleFunc("/doc/", h.handleDoc)
	mux.HandleFunc("/changedoc", h.handleChangedoc)
	mux.HandleFunc("/robots.txt", handleRobots)
	h.mux = mux

	if err := h.disco(); err != nil {
		return nil, err
	}

	authConfig, err := appConfig()
	if err != nil {
		return nil, err
	}
	if authConfig == nil || authConfig.Auth == "" {
		return h, nil
	}
	userpass := strings.Split(authConfig.Auth, ":")
	if len(userpass) != 3 {
		return nil, fmt.Errorf("invalid auth string syntax. got %q, want \"userpass:username:password\"", authConfig.Auth)
	}
	am := auth.NewBasicAuth(userpass[1], userpass[2])
	requireAuth := func(h http.Handler, am auth.AuthMode) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if auth.AllowedWithAuth(am, req, auth.OpAll) {
				h.ServeHTTP(rw, req)
				return
			} else {
				if us, ok := am.(auth.UnauthorizedSender); ok {
					if us.SendUnauthorized(rw, req) {
						return
					}
				}
				rw.Header().Set("WWW-Authenticate", "Basic realm=scanning cabinet")
				rw.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(rw, "<html><body><h1>Unauthorized</h1>")
			}
		})
	}

	return requireAuth(h, am), nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.mux == nil {
		http.Error(w, "handler not properly initialized", http.StatusInternalServerError)
		return
	}
	h.mux.ServeHTTP(w, r)
}

type rootData struct {
	BaseURL      string
	Tags         string
	Media        []MediaObjectVM
	SearchedDocs []DocumentVM
	UntaggedDocs []DocumentVM
	UpcomingDocs []DocumentVM
	TopMessage   template.HTML
	ErrorMessage string
	AllTags      []string
}

func (h *handler) disco() error {
	var err error
	server := os.Getenv("CAMLI_API_HOST")
	if server == "" {
		server, err = h.cl.BlobRoot()
		if err != nil {
			return fmt.Errorf("CAMLI_API_HOST var not set, and client could not discover server blob root: %v", err)
		}
	}
	h.server = server

	// TODO(mpl): setup our own signer if we got our own key and stuff.
	signer, err := h.cl.ServerPublicKeyBlobRef()
	if err != nil {
		return fmt.Errorf("client has no signing capability and server can't sign for us either: %v", err)
	}
	h.signer = signer
	return nil
}

func (h *handler) handleRoot(w http.ResponseWriter, r *http.Request) {
	topMessage := ""
	if saved_doc := r.FormValue("saved_doc"); saved_doc != "" {
		topMessage = fmt.Sprintf("Saved <a href='%sdoc/%s'>doc %s</a>", h.baseURL, saved_doc, saved_doc)
	}
	errorMessage := r.FormValue("error_message")

	limit := maxScan
	if limitparam := r.FormValue("limit"); limitparam != "" {
		newlimit, err := strconv.Atoi(limitparam)
		if err == nil {
			limit = newlimit
		}
	}

	var (
		movm         []MediaObjectVM
		searchedDocs []DocumentVM
		allTags      []string
	)
	tags := newSeparatedString(r.FormValue("tags"))
	docs, err := h.fetchDocuments(limit, searchOpts{tags: tags})
	if err != nil {
		httputil.ServeError(w, r, err)
		return
	}

	if len(tags) != 0 {
		searchedDocs = MakeDocumentViewModels(docs)
		// We've just done a search, in which case we don't show the scans,
		// so no need to look for them. Nor do we look for/show the tags cloud.
	} else {
		// fetch media objects
		mediaObjects, err := h.fetchScans(limit)
		if err != nil {
			httputil.ServeError(w, r, err)
			return
		}
		movm = MakeMediaObjectViewModels(mediaObjects)
		// TODO(mpl): we effectively have to fetch all the documents to get all
		// the tags - which seems wasteful in itself already - so we should
		// probably then use these docs to derive ourselves locally: any tagged
		// search result, upcoming, untagged. That is, instead of doing a fetch for
		// each of these, which unnecessarily burdens the server (and does slow
		// requests). Or we don't do a tags cloud.
		// Leaving it as is for now because 1) we don't do that many requests,
		// 2) it's interesting to test various requests on our search handler.
		allTags, err = h.fetchTags()
		if err != nil {
			httputil.ServeError(w, r, err)
			return
		}
	}

	// fetch upcoming documents
	upcoming, err := h.fetchDocuments(maxDue, searchOpts{due: true})
	if err != nil {
		httputil.ServeError(w, r, err)
		return
	}

	// fetch untagged documents
	untagged, err := h.fetchDocuments(limit, searchOpts{untagged: true})
	if err != nil {
		httputil.ServeError(w, r, err)
		return
	}

	d := rootData{
		BaseURL:      h.baseURL,
		Tags:         strings.Join(tags, ", "),
		Media:        movm,
		SearchedDocs: searchedDocs,
		UntaggedDocs: MakeDocumentViewModels(untagged),
		UpcomingDocs: MakeDocumentViewModels(upcoming),
		TopMessage:   template.HTML(topMessage),
		ErrorMessage: errorMessage,
		AllTags:      allTags,
	}
	if err := rootTemplate.Execute(w, d); err != nil {
		httputil.ServeError(w, r, err)
		return
	}
}

func (h *handler) handleUploadURL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s", h.baseURL+"upload")
	return
}

func (h *handler) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "not a POST", http.StatusMethodNotAllowed)
		return
	}

	mr, err := r.MultipartReader()
	if err != nil {
		httputil.ServeError(w, r, err)
		return
	}

	k := 0
	var br blob.Ref
	var fileName string
	cr := countingReader{}
	for {
		k++
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			httputil.ServeError(w, r, err)
			return
		}
		// TODO(mpl): when the upload tool is ported to Go, and if it can support sending modtime,
		// then use it here, with WriteFileFromReaderWithModTime behind the scenes.
		name := part.FileName()
		if name == "" {
			continue
		} else {
			fileName = path.Base(name)
		}
		cr.r = part
		br, err = h.cl.UploadFile(fileName, &cr, nil)
		if err != nil {
			httputil.ServeError(w, r, fmt.Errorf("could not write %v to blobserver: %v", fileName, err))
			return
		}
	}

	// TODO(mpl): do not create document if already exists one for this file ? I don't think original app did that though.
	_, err = h.createScan(mediaObject{
		content:  br,
		creation: time.Now(),
	})
	if err != nil {
		httputil.ServeError(w, r, fmt.Errorf("could not create scan object for %v: %v", fileName, err))
		return
	}
}

type countingReader struct {
	hdr []byte
	n   int
	r   io.Reader
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if c.n < 1024 {
		c.hdr = append(c.hdr, p...)
	}
	c.n += n
	return n, err
}

func (c *countingReader) Mime() string {
	return magic.MIMEType(c.hdr)
}

func (h *handler) handleResource(w http.ResponseWriter, r *http.Request) {
	m := resourcePattern.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.Error(w, "invalid resource URL", http.StatusBadRequest)
		return
	}
	scanRef, ok := blob.Parse(m[1])
	if !ok {
		http.Error(w, fmt.Sprintf("invalid resource blobref: %q", m[1]), http.StatusBadRequest)
		return
	}

	mediaObject, err := h.fetchScan(scanRef)
	if err != nil {
		if err == os.ErrNotExist {
			http.Error(w, fmt.Sprintf("%v not found", scanRef), http.StatusNotFound)
			return
		}
		httputil.ServeError(w, r, fmt.Errorf("resource %v not found: %v", scanRef, err))
		return
	}

	// TODO(mpl): cache and thumbmeta
	ih := &camliserver.ImageHandler{
		Fetcher:   h.cl,
		MaxWidth:  search.MaxImageSize,
		MaxHeight: search.MaxImageSize,
		Square:    false,
		// TODO(mpl): make the image pkg default to the below when ResizeSem is nil
		ResizeSem: syncutil.NewSem(constants.DefaultMaxResizeMem),
	}

	if resizeParam := r.FormValue("resize"); resizeParam != "" {
		resized, err := strconv.Atoi(resizeParam)
		if err != nil {
			httputil.ServeError(w, r, fmt.Errorf("bogus resize param %q: %v", resizeParam, err))
			return
		}
		ih.MaxWidth = resized
		ih.MaxHeight = resized
	}
	ih.ServeHTTP(w, r, mediaObject.content)
	return
}

func (h *handler) handleMakedoc(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "not a POST", http.StatusMethodNotAllowed)
		return
	}

	// gather the media_ids from the form into scanKeys
	if r.Form == nil {
		r.ParseMultipartForm(1)
	}
	refs := r.Form["blobref"]
	var pages []blob.Ref
	for _, ref := range refs {
		br, ok := blob.Parse(ref)
		if !ok {
			httputil.ServeError(w, r, fmt.Errorf("invalid page blobRef %q", ref))
			return
		}
		pages = append(pages, br)
	}

	newDoc := document{
		pages:    pages,
		creation: time.Now(),
	}

	pn, err := h.persistDocAndPages(newDoc)
	if err != nil {
		httputil.ServeError(w, r, fmt.Errorf("could not save document: %v", err))
		return
	}
	newDoc.blobRef = pn
	http.Redirect(w, r, fmt.Sprintf("%s%s?size=1200", h.baseURL, newDoc.displayURL()), http.StatusFound)
}

func (h *handler) handleDoc(w http.ResponseWriter, r *http.Request) {
	urlFields := strings.Split(r.URL.Path, "/")
	if len(urlFields) < 3 {
		http.Error(w, "no document blobref", http.StatusBadRequest)
		return
	}

	docRef, ok := blob.Parse(urlFields[2])
	if !ok {
		http.Error(w, fmt.Sprintf("invalid document blobref: %q", urlFields[2]), http.StatusBadRequest)
		return
	}
	document, err := h.fetchDocument(docRef)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("%s?error_message=DocRef+%s+not+found", h.baseURL, docRef), http.StatusFound)
		return
	}

	var pages []mediaObject
	for _, v := range document.pages {
		// TODO(mpl): group fetch ?
		page, err := h.fetchScan(v)
		if err != nil {
			httputil.ServeError(w, r, fmt.Errorf("could not fetch page %v for document %v: %v", v, document.blobRef, err))
			return
		}
		pages = append(pages, page)
	}
	var size int
	size = 1200
	if sizeParam := r.FormValue("size"); sizeParam != "" {
		sizeint, err := strconv.Atoi(sizeParam)
		if err != nil {
			httputil.ServeError(w, r, fmt.Errorf("invalide size param %q: %v", sizeParam, err))
			return
		}
		size = sizeint
	}
	show_single_list := size > 600

	d := struct {
		BaseURL        string
		Pages          []MediaObjectVM
		Doc            DocumentVM
		ShowSingleList bool
		Size           int
	}{
		BaseURL:        h.baseURL,
		Pages:          MakeMediaObjectViewModels(pages),
		Doc:            document.MakeViewModel(),
		ShowSingleList: show_single_list,
		Size:           size,
	}
	if err := docTemplate.Execute(w, d); err != nil {
		httputil.ServeError(w, r, fmt.Errorf("could not serve doc template: %v", err))
		return
	}
}

func (h *handler) handleChangedoc(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "not a POST", http.StatusMethodNotAllowed)
		return
	}

	docRef, ok := blob.Parse(r.FormValue("docref"))
	if !ok {
		httputil.ServeError(w, r, fmt.Errorf("invalid document blobRef %q", r.FormValue("docref")))
		return
	}

	mode := r.FormValue("mode")
	if mode == "break" {
		if err := h.breakAndDeleteDoc(docRef); err != nil {
			httputil.ServeError(w, r, fmt.Errorf("could not delete document %v: %v", docRef, err))
			return
		}
		fmt.Fprintf(w, "<html><body>[&lt;&lt; <a href='%s'>Back</a>] Doc %s deleted and images broken out as un-annotated.</body></html>", h.baseURL, docRef)
		return
	}
	if mode == "delete" {
		if err := h.deleteDocAndImages(docRef); err != nil {
			httputil.ServeError(w, r, fmt.Errorf("could not do full delete of %v: %v", docRef, err))
			return
		}
		fmt.Fprintf(w, "<html><body>[&lt;&lt; <a href='%s'>Back</a>] Doc %s and its images deleted.</body></html>", h.baseURL, docRef)
		return
	}

	document := &document{}
	document.physicalLocation = r.FormValue("physical_location")
	document.title = r.FormValue("title")
	document.tags = newSeparatedString(r.FormValue("tags"))

	docDate, err := dateOrZero(r.FormValue("date"), DateformatYyyyMmDd)
	if err != nil {
		httputil.ServeError(w, r, fmt.Errorf("could not assign new date to document: %v", err))
		return
	}
	document.docDate = docDate

	duedate, err := dateOrZero(r.FormValue("due_date"), DateformatYyyyMmDd)
	if err != nil {
		httputil.ServeError(w, r, fmt.Errorf("could not assign new due date to document: %v", err))
		return
	}
	document.dueDate = duedate

	if err := h.updateDocument(docRef, document); err != nil {
		httputil.ServeError(w, r, fmt.Errorf("could not update document %v: %v", docRef, err))
		return
	}

	http.Redirect(w, r, fmt.Sprintf("%s?saved_doc=%s", h.baseURL, docRef), http.StatusFound)
}

func handleRobots(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
}
