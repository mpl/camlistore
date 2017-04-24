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

// package importshare provides a method to import blobs shared from another
// Camlistore server.
package importshare

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"camlistore.org/pkg/auth"
	"camlistore.org/pkg/blob"
	"camlistore.org/pkg/client"
	// TODO(mpl): get index.NewBlobSniffer out of index so we don't have to
	// import it? I'll measure how it affects the web UI size to decide if
	// it's worth doing.
	"camlistore.org/pkg/index"
	"camlistore.org/pkg/schema"

	"go4.org/types"
)

// forwarder copies blobs from src to dest.
type forwarder struct {
	src  *client.Client
	dest *client.Client

	mu     sync.RWMutex
	seen   int // files seen. for statistics, as web UI feedback.
	copied int // files actually copied. for statistics, as web UI feedback.

	updateDialog func(message string) // to refresh the import progress on the dialog that calls this importer.
}

// A little less than the sniffer will take, so we don't truncate.
const sniffSize = 900 * 1024

// forward fetches and copies the things that blobs point to, not just blobs.
func (fw *forwarder) forward(br blob.Ref) error {
	src := fw.src
	dest := fw.dest
	rc, _, err := src.Fetch(br)
	if err != nil {
		return err
	}
	rcc := types.NewOnceCloser(rc)
	defer rcc.Close()

	sniffer := index.NewBlobSniffer(br)
	_, err = io.CopyN(sniffer, rc, sniffSize)
	if err != nil && err != io.EOF {
		return err
	}

	sniffer.Parse()
	b, ok := sniffer.SchemaBlob()
	if !ok {
		// TODO(mpl): if they tried to import an "assembled" share URL of a file, cope with it?
		return fmt.Errorf("%q: not a Camlistore schema. Maybe an assembled URL?", br)
	}
	rcc.Close()

	switch b.Type() {
	case "directory":
		if _, err := fw.dest.UploadBlob(b); err != nil {
			return err
		}
		ssbr, ok := b.DirectoryEntries()
		if !ok {
			return fmt.Errorf("%q not actually a directory", br)
		}
		return fw.forward(ssbr)
	case "static-set":
		if _, err := fw.dest.UploadBlob(b); err != nil {
			return err
		}
		// TODO(mpl): it seems like with a deep enough tree the number of goroutines could explode, so maybe revisit?
		const numWorkers = 10
		type work struct {
			br   blob.Ref
			errc chan<- error
		}
		members := b.StaticSetMembers()
		workc := make(chan work, len(members))
		defer close(workc)
		for i := 0; i < numWorkers; i++ {
			go func() {
				for wi := range workc {
					wi.errc <- fw.forward(wi.br)
				}
			}()
		}
		var errcs []<-chan error
		for _, mref := range members {
			errc := make(chan error, 1)
			errcs = append(errcs, errc)
			workc <- work{mref, errc}
		}
		for _, errc := range errcs {
			if err := <-errc; err != nil {
				return err
			}
		}
		return nil
	case "file":
		fr, err := schema.NewFileReader(src, br)
		if err != nil {
			return fmt.Errorf("NewFileReader: %v", err)
		}
		defer fr.Close()
		fw.mu.Lock()
		fw.seen++
		fw.mu.Unlock()
		if _, err := schema.WriteFileMap(dest, b.Builder(), fr); err != nil {
			return err
		}
		fw.mu.Lock()
		fw.copied++
		fw.mu.Unlock()
		return nil
	// TODO(mpl): other camliTypes, at least symlink.
	default:
		return errors.New("unknown blob type: " + b.Type())
	}
}

func forward(authToken, shareURL string, updateDialog func(string)) error {
	am, err := auth.NewTokenAuth(authToken)
	if err != nil {
		return fmt.Errorf("error setting up auth for importing share: %v", err)
	}
	dest := client.NewFromParams("", am, client.OptionSameOrigin(true),
		client.OptionTransportConfig(&client.TransportConfig{Default: true}))
	src, shared, err := client.NewFromShareRoot(shareURL, client.OptionParamsOnly(true),
		client.OptionTransportConfig(&client.TransportConfig{Default: true}))
	if err != nil {
		return err
	}
	c := make(chan struct{})
	fw := forwarder{
		updateDialog: updateDialog,
		src:          src,
		dest:         dest,
	}
	go func() {
		for {
			select {
			case <-c:
				fw.updateStatsMessage(true)
				// Ack to the main goroutine that we've done our last refresh
				c <- struct{}{}
				return
			default:
			}
			fw.updateStatsMessage(false)
			time.Sleep(2 * time.Second)
		}
	}()
	// TODO(mpl): for some reason, if I try to deal with the returned error
	// in the caller (Import), gopherjs freaks out when calling err.Error() (to
	// pass it to updateDialog), so we do it here and now instead. Try to build
	// a repro for upstream.
	err = fw.forward(shared)
	// first free the statistics goroutine
	c <- struct{}{}
	// And wait for it to be done with the last refresh
	<-c
	// And then finally print the error message, if any. Which should be
	// done in the caller, but see TODO above.
	if err != nil {
		println(err.Error())
		updateDialog(err.Error())
	}
	return err
}

func (fw forwarder) updateStatsMessage(final bool) {
	fw.mu.RLock()
	seen := fw.seen
	copied := fw.copied
	fw.mu.RUnlock()
	if final {
		fw.updateDialog(fmt.Sprintf("Done - %d/%d files imported", copied, seen))
		return
	}
	fw.updateDialog(fmt.Sprintf("Working - %d/%d files imported", copied, seen))
}

// Import fetches all the blobs shared by shareURL and forwards them to our
// blobserver, using authToken to authenticate with it. updateDialog is called
// regularly to refresh the importing progress message on the caller (a web UI
// element).
func Import(authToken, shareURL string, updateDialog func(message string)) {
	go func() {
		// ignore returned error here, as gopherjs freaks out for some
		// reason if I call err.Error() here. So it's processed at the end
		// of the forward call instead.
		forward(authToken, shareURL, updateDialog)
	}()
}
