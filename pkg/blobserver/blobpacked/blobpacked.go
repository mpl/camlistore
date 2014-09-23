/*
Copyright 2014 The Camlistore AUTHORS

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

/*
Package blobpacked registers the "blobpacked" blobserver storage type,
storing blobs initially as one physical blob per logical blob, but then
rearranging little physical blobs into large contiguous blobs organized by
how they'll likely be accessed. An index tracks the mapping from logical to
physical blobs.

Example low-level config:

     "/storage/": {
         "handler": "storage-blobpacked",
         "handlerArgs": {
            "smallBlobs": "/small/",
            "largeBlobs": "/large/",
            "metaIndex": {
               "type": "mysql",
                .....
            }
          }
     }

The resulting large blobs are valid zip files. Those blobs may up be up to
16 MB and contain the original contiguous file (or fractions of it), as well
as metadata about how the file is cut up. The zip file will have the
following structure:

    foo.jpg       (or whatever)
    camlistore/sha1-beb1df0b75952c7d277905ad14de71ef7ef90c44.json (some file ref)
    camlistore/sha1-a0ceb10b04403c9cc1d032e07a9071db5e711c9a.json (some bytes ref)
    camlistore/sha1-7b4d9c8529c27d592255c6dfb17188493db96ccc.json (another bytes ref)
    camlistore/camlistore-pack-manifest.json

The camlistore-pack-manifest.json is documented on the exported
Manifest type. It looks like this:

    {
      "wholeRef": "sha1-0e64816d731a56915e8bb4ae4d0ac7485c0b84da",
      "wholeSize": 2962227200, // 2.8GB; so will require ~176-180 16MB chunks
      "wholePartIndex": 17,    // 0-based
      "dataBlobsOrigin": "sha1-355705cf62a56669303d2561f29e0620a676c36e",
      "dataBlobs": [
          {"blob": "sha1-f1d2d2f924e986ac86fdf7b36c94bcdf32beec15", "offset": 0, "size": 273048},
          {"blob": "sha1-e242ed3bffccdf271b7fbaf34ed72d089537b42f", "offset": 273048, "size": 112783},
          {"blob": "sha1-6eadeac2dade6347e87c0d24fd455feffa7069f0", "offset": 385831, ...},
          {"blob": "sha1-beb1df0b75952c7d277905ad14de71ef7ef90c44", "offset": ...},
          {"blob": "sha1-a0ceb10b04403c9cc1d032e07a9071db5e711c9a", "offset": ...},
          {"blob": "sha1-7b4d9c8529c27d592255c6dfb17188493db96ccc", "offset": ...}
      ],
    }

The 'blobs' property list all the logical blobs. Those are the blobs that
Camlistore reports that it has and were previously stored individually. Now
they're stored as part of a larger blob. The manifest.json ensures that if
the metadata index is lost, the data can be reconstructed from the raw zip
files (using the BlobStreamer interface).

The 'wholeRef' property specifies which large file that this zip is building
up.  If the file is less than 15.5 MB or so (leaving room for the zip
overhead and manifest size), it will probably all be in one zip and the
first file in the zip will be the whole thing. Otherwise it'll be cut across
multiple zip files, each no larger than 16MB. In that case, each part of the
file will have a different 'wholePartIndex' number, starting at index
0. Each will have the same 'wholeSize'.
*/

package blobpacked

// TODO: BlobStreamer using the zip manifests, for recovery.
// TODO: option to not even delete from the source?

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"

	"camlistore.org/pkg/blob"
	"camlistore.org/pkg/blobserver"
	"camlistore.org/pkg/constants"
	"camlistore.org/pkg/context"
	"camlistore.org/pkg/jsonconfig"
	"camlistore.org/pkg/pools"
	"camlistore.org/pkg/schema"
	"camlistore.org/pkg/sorted"
	"camlistore.org/pkg/strutil"
	"camlistore.org/pkg/syncutil"
	"camlistore.org/third_party/go/pkg/archive/zip"
)

// TODO: evaluate whether this should even be 0, to keep the schema blobs together at least.
// Files under this size aren't packed.
const packThreshold = 512 << 10

// overhead for zip magic, file headers, TOC, footers. Without measuring accurately,
// saying 50kB for now.
const zipOverhead = 50 << 10

// meta key prefixes
const (
	blobMetaPrefix      = "b:"
	blobMetaPrefixLimit = "b;"

	wholeMetaPrefix = "w:"
)

type subFetcherStorage interface {
	blobserver.Storage
	blob.SubFetcher
}

type storage struct {
	small blobserver.Storage
	large subFetcherStorage

	// meta key -> value rows are:
	//
	// For logical blobs, "b:" prefix:
	//   b:sha1-xxxx -> "<size> s"
	//   b:sha1-xxxx -> "<size> l <big-blobref> <offset_u32>"
	//
	// For wholerefs:
	//   w:sha1-xxxx(wholeref) -> "<nbytes_total_u64> <nchunks_u32>"
	// Then for each big nchunk of the file:
	//   w:sha1-xxxx:0 -> "<chunk-blobref> <offset-in-whole_u64> <length_u32>"
	//   w:sha1-xxxx:1 -> "<chunk-blobref> <offset_in-whole-u64> <length_u32>"
	//   ...
	meta sorted.KeyValue

	// assumeSmall determines whether a meta lookup failure falls
	// back to assuming a blob might exist on the small
	// storage. This is useful for lazy migrations to
	// blobpacked. This also affects enumerate.
	assumeSmall bool

	// If non-zero, the maximum size of a zip blob.
	// It defaults to constants.MaxBlobSize.
	forceMaxZipBlobSize int

	packGate *syncutil.Gate
}

var (
	_ blobserver.BlobStreamer = (*storage)(nil)
)

func (s *storage) String() string {
	return fmt.Sprintf("\"blobpacked\" storage")
}

func (s *storage) init() {
	s.packGate = syncutil.NewGate(10)
}

func (s *storage) maxZipBlobSize() int {
	if s.forceMaxZipBlobSize > 0 {
		return s.forceMaxZipBlobSize
	}
	return constants.MaxBlobSize
}

func init() {
	blobserver.RegisterStorageConstructor("blobpacked", blobserver.StorageConstructor(newFromConfig))
}
func newFromConfig(ld blobserver.Loader, conf jsonconfig.Obj) (blobserver.Storage, error) {
	var (
		smallPrefix = conf.RequiredString("smallBlobs")
		largePrefix = conf.RequiredString("largeBlobs")
		metaConf    = conf.RequiredObject("metaIndex")
		assumeSmall = conf.OptionalBool("assumeSmall", true)
	)
	if err := conf.Validate(); err != nil {
		return nil, err
	}
	small, err := ld.GetStorage(smallPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to load smallBlobs at %s: %v", smallPrefix, err)
	}
	large, err := ld.GetStorage(largePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to load largeBlobs at %s: %v", largePrefix, err)
	}
	largeSubber, ok := large.(subFetcherStorage)
	if !ok {
		return nil, fmt.Errorf("largeBlobs at %q of type %T doesn't support fetching sub-ranges of blobs",
			largePrefix, large)
	}
	meta, err := sorted.NewKeyValue(metaConf)
	if err != nil {
		return nil, fmt.Errorf("failed to setup blobpacked metaIndex: %v", err)
	}
	sto := &storage{
		small:       small,
		large:       largeSubber,
		meta:        meta,
		assumeSmall: assumeSmall,
	}
	sto.init()
	return sto, nil
}

func (s *storage) Close() error {
	return nil
}

type meta struct {
	exists   bool
	size     uint32
	largeRef blob.Ref // if invalid, then on small if exists
	largeOff uint32
}

// if not found, err == nil.
func (s *storage) getMetaRow(br blob.Ref) (meta, error) {
	v, err := s.meta.Get(blobMetaPrefix + br.String())
	if err == sorted.ErrNotFound {
		return meta{}, nil
	}
	return parseMetaRow([]byte(v))
}

var singleSpace = []byte{' '}

// parses one of:
// "<size_u32> s"
// "<size_u32> l <big-blobref> <big-offset>"
func parseMetaRow(v []byte) (m meta, err error) {
	row := v
	sp := bytes.IndexByte(v, ' ')
	if sp < 1 || sp == len(v)-1 {
		return meta{}, fmt.Errorf("invalid metarow %q", v)
	}
	m.exists = true
	size, err := strutil.ParseUintBytes(v[:sp], 10, 32)
	if err != nil {
		return meta{}, fmt.Errorf("invalid metarow size %q", v)
	}
	m.size = uint32(size)
	v = v[sp+1:]
	switch v[0] {
	default:
		return meta{}, fmt.Errorf("invalid metarow type %q", v)
	case 's':
		if len(v) > 1 {
			return meta{}, fmt.Errorf("invalid small metarow %q", v)
		}
		return
	case 'l':
		if len(v) < 2 || v[1] != ' ' {
			err = errors.New("length")
			break
		}
		v = v[2:] // remains: "<big-blobref> <big-offset>"
		if bytes.Count(v, singleSpace) != 1 {
			err = errors.New("number of spaces")
			break
		}
		sp := bytes.IndexByte(v, ' ')
		largeRef, ok := blob.ParseBytes(v[:sp])
		if !ok {
			err = fmt.Errorf("bad blobref %q", v[:sp])
			break
		}
		m.largeRef = largeRef
		off, err := strutil.ParseUintBytes(v[sp+1:], 10, 32)
		if err != nil {
			break
		}
		m.largeOff = uint32(off)
		return m, nil
	}
	return meta{}, fmt.Errorf("invalid metarow %q: %v", row, err)
}

func parseMetaRowSizeOnly(v []byte) (size uint32, err error) {
	sp := bytes.IndexByte(v, ' ')
	if sp < 1 || sp == len(v)-1 {
		return 0, fmt.Errorf("invalid metarow %q", v)
	}
	size64, err := strutil.ParseUintBytes(v[:sp], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid metarow size %q", v)
	}
	return uint32(size64), nil
}

func (s *storage) ReceiveBlob(br blob.Ref, source io.Reader) (sb blob.SizedRef, err error) {
	buf := pools.BytesBuffer()
	defer pools.PutBuffer(buf)

	if _, err := io.Copy(buf, source); err != nil {
		return sb, err
	}
	size := uint32(buf.Len())
	isFile := false
	fileBlob, err := schema.BlobFromReader(br, bytes.NewReader(buf.Bytes()))
	if err == nil && fileBlob.Type() == "file" {
		isFile = true
	}
	meta, err := s.getMetaRow(br)
	if err != nil {
		return sb, err
	}
	if meta.exists {
		sb = blob.SizedRef{Size: size, Ref: br}
	} else {
		sb, err = s.small.ReceiveBlob(br, buf)
		if err != nil {
			return sb, err
		}
		if err := s.meta.Set(blobMetaPrefix+br.String(), fmt.Sprintf("%d s", size)); err != nil {
			return sb, err
		}
	}
	if !isFile || meta.largeRef.Valid() || fileBlob.PartsSize() < packThreshold {
		return sb, nil
	}

	// Pack the blob.
	s.packGate.Start()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer s.packGate.Done()
		defer wg.Done()
		if err := s.packFile(br); err != nil {
			log.Printf("Error packing file %s: %v", br, err)
		}
	}()
	wg.Wait()
	return sb, nil
}

func (s *storage) Fetch(br blob.Ref) (io.ReadCloser, uint32, error) {
	m, err := s.getMetaRow(br)
	if err != nil {
		return nil, 0, err
	}
	if !m.exists {
		if s.assumeSmall {
			return s.fallbackFetch(br)
		}
		return nil, 0, os.ErrNotExist
	}
	if !m.largeRef.Valid() {
		return s.small.Fetch(br)
	}
	rc, err := s.large.SubFetch(m.largeRef, int64(m.largeOff), int64(m.size))
	if err != nil {
		return nil, 0, err
	}
	return rc, m.size, nil
}

func (s *storage) fallbackFetch(br blob.Ref) (io.ReadCloser, uint32, error) {
	rc, size, err := s.small.Fetch(br)
	if err != nil {
		return nil, 0, err
	}
	// TODO: populate meta? might just be redundant information, with both
	// having an index. perhaps we should just always assumeSmall and remove
	// the "s nnnnn" meta rows altogether.
	return rc, size, err
}

func (s *storage) RemoveBlobs(blobs []blob.Ref) error {
	// TODO: how to support? only delete from index? delete from
	// small if only there?  if in big file, re-break apart into
	// its chunks? no reverse index from big chunk to all its
	// constituent chunks, though. I suppose we could read the chunks
	// from the metadata file in the zip.
	return errors.New("not implemented")
}

func (s *storage) StatBlobs(dest chan<- blob.SizedRef, blobs []blob.Ref) (err error) {
	for _, br := range blobs {
		m, err := s.getMetaRow(br)
		if err != nil {
			return err
		}
		if m.exists {
			dest <- blob.SizedRef{Ref: br, Size: m.size}
		}
	}
	return nil
}

func (s *storage) EnumerateBlobs(ctx *context.Context, dest chan<- blob.SizedRef, after string, limit int) (err error) {
	if s.assumeSmall {
		return blobserver.MergedEnumerate(ctx, dest, []blobserver.BlobEnumerator{
			s.small,
			enumerator{s},
		}, after, limit)
	}
	return enumerator{s}.EnumerateBlobs(ctx, dest, after, limit)
}

// enumerator implements EnumerateBlobs.
type enumerator struct {
	*storage
}

func (s enumerator) EnumerateBlobs(ctx *context.Context, dest chan<- blob.SizedRef, after string, limit int) (err error) {
	defer close(dest)
	t := s.meta.Find(blobMetaPrefix+after, blobMetaPrefixLimit)
	defer func() {
		closeErr := t.Close()
		if err == nil {
			err = closeErr
		}
	}()
	n := 0
	afterb := []byte(after)
	for n < limit && t.Next() {
		key := t.KeyBytes()[len(blobMetaPrefix):]
		if n == 0 && bytes.Equal(key, afterb) {
			continue
		}
		n++
		br, ok := blob.ParseBytes(key)
		if !ok {
			return fmt.Errorf("unknown key %q in meta index", t.Key())
		}
		size, err := parseMetaRowSizeOnly(t.ValueBytes())
		if err != nil {
			return err
		}
		dest <- blob.SizedRef{Ref: br, Size: size}
	}
	return nil
}

func (s *storage) StreamBlobs(ctx *context.Context, dest chan<- *blob.Blob, contToken string, limitBytes int64) (nextContinueToken string, err error) {
	defer close(dest)
	// Continuation token is:
	// "s*" if we're in the small blobs,
	// "l*" if we're in the large blobs,
	// First it streams from small (if available, else enumerates)
	// Then it streams from large (if available, else enumerates),
	// and for each large, streams the contents of the zips.
	panic("TODO")
}

func (s *storage) blobSource() blob.Fetcher {
	// TODO: find or use a cache. make all uploaded blobs to the
	// server go to the cache too. Put the cache on fast local
	// disk or memory. Make sure it works well no GCE too, where
	// reconstruction of the packFile in the common case should
	// never do GET requests to Google Cloud Storage.
	// For now, just use the small store:
	return s.small
}

func (s *storage) packFile(fileRef blob.Ref) error {
	fr, err := schema.NewFileReader(s.blobSource(), fileRef)
	if err != nil {
		return err
	}
	return newPacker(s, fileRef, fr).pack()
}

func newPacker(s *storage, fileRef blob.Ref, fr *schema.FileReader) *packer {
	return &packer{
		s:            s,
		src:          s.blobSource(),
		fileRef:      fileRef,
		fr:           fr,
		dataSize:     map[blob.Ref]uint32{},
		schemaBlob:   map[blob.Ref]*blob.Blob{},
		schemaParent: map[blob.Ref][]blob.Ref{},
	}
}

// A packer writes a file out
type packer struct {
	s       *storage
	fileRef blob.Ref
	src     blob.Fetcher
	fr      *schema.FileReader

	wholeRef  blob.Ref
	wholeSize int64

	dataRefs []blob.Ref // in order
	dataSize map[blob.Ref]uint32

	schemaRefs   []blob.Ref // in order, but irrelevant
	schemaBlob   map[blob.Ref]*blob.Blob
	schemaParent map[blob.Ref][]blob.Ref // data blob -> its parent/ancestor schema blob(s)

	chunksRemain []blob.Ref
	zips         []writtenZip
}

type writtenZip struct {
	blob.SizedRef
	dataRefs []blob.Ref
}

func (pk *packer) pack() error {
	if err := pk.scanChunks(); err != nil {
		return err
	}

	// TODO: decide as a fuction of schemaRefs and dataRefs
	// already in s.large whether it makes sense to still compact
	// this from a savings standpoint. For now we just always do.
	// Maybe we'd have knobs in the future. Ideally not.

	// Don't pack a file if we already have its wholeref stored
	// otherwise (perhaps under a different filename). But that means
	// we have to compute its wholeref first. We assume the blobSource
	// will cache these lookups so it's not too expensive to do two
	// passes over the input.
	h := blob.NewHash()
	var err error
	pk.wholeSize, err = io.Copy(h, pk.fr)
	if err != nil {
		return err
	}
	pk.wholeRef = blob.RefFromHash(h)
	if _, err = pk.s.meta.Get(wholeMetaPrefix + pk.wholeRef.String()); err == nil {
		// Nil error means there was some knowledge of this wholeref.
		return fmt.Errorf("already have wholeref %v packed; not packing again", pk.wholeRef)
	} else if err != sorted.ErrNotFound {
		return err
	}

	pk.chunksRemain = pk.dataRefs
	var trunc blob.Ref
MakingZips:
	for len(pk.chunksRemain) > 0 {
		if err := pk.writeAZip(trunc); err != nil {
			if needTrunc, ok := err.(needsTruncatedAfterError); ok {
				trunc = needTrunc.Ref
				continue MakingZips
			}
			return err
		}
		trunc = blob.Ref{}
	}
	return nil
}

func (pk *packer) scanChunks() error {
	schemaSeen := map[blob.Ref]bool{}
	return pk.fr.ForeachChunk(func(schemaPath []blob.Ref, p schema.BytesPart) error {
		if !p.BlobRef.Valid() {
			return errors.New("sparse files are not packed")
		}
		if p.Offset != 0 {
			// TODO: maybe care about this later, if we ever start making
			// these sorts of files.
			return errors.New("file uses complicated schema. not packing.")
		}
		pk.schemaParent[p.BlobRef] = append([]blob.Ref(nil), schemaPath...) // clone it
		pk.dataSize[p.BlobRef] = uint32(p.Size)
		for _, schemaRef := range schemaPath {
			if schemaSeen[schemaRef] {
				continue
			}
			schemaSeen[schemaRef] = true
			pk.schemaRefs = append(pk.schemaRefs, schemaRef)
			if b, err := blob.FromFetcher(pk.src, schemaRef); err != nil {
				return err
			} else {
				pk.schemaBlob[schemaRef] = b
			}
		}
		pk.dataRefs = append(pk.dataRefs, p.BlobRef)
		return nil
	})
}

// needsTruncatedAfterError is returend by writeAZip if it failed in its estimation and the zip file
// was over the 16MB (or whatever) max blob size limit. In this case the caller tries again
type needsTruncatedAfterError struct{ blob.Ref }

func (e needsTruncatedAfterError) Error() string { return "needs truncation after " + e.Ref.String() }

// check should only be used for things which really shouldn't ever happen, but should
// still be checked. If there is interesting logic in the 'else', then don't use this.
func check(err error) {
	if err != nil {
		b := make([]byte, 2<<10)
		b = b[:runtime.Stack(b, false)]
		log.Printf("Unlikely error condition triggered: %v at %s", err, b)
		panic(err)
	}
}

// trunc is a hint about which blob to truncate after. It may be zero.
// If the returned error is of type 'needsTruncatedAfterError', then
// the zip should be attempted to be written again, but truncating the
// data after the listed blob.
func (pk *packer) writeAZip(trunc blob.Ref) (err error) {
	defer func() {
		if e := recover(); e != nil {
			if v, ok := e.(error); ok && err == nil {
				err = v
			} else {
				panic(e)
			}
		}
	}()
	mf := Manifest{
		WholeRef:       pk.wholeRef,
		WholeSize:      pk.wholeSize,
		WholePartIndex: len(pk.zips),
	}
	var zbuf bytes.Buffer
	cw := &countWriter{w: &zbuf}
	zw := zip.NewWriter(cw)

	var approxSize int // can't use zbuf.Len because zw buffers
	var dataRefsWritten []blob.Ref
	var schemaBlobSeen = map[blob.Ref]bool{}
	var schemaBlobs []blob.Ref // to add after the main file

	baseFileName := pk.fr.FileName()
	if strings.Contains(baseFileName, "/") || strings.Contains(baseFileName, "\\") {
		return fmt.Errorf("File schema blob %v filename had a slash in it: %q", pk.fr.SchemaBlobRef(), baseFileName)
	}
	fh := &zip.FileHeader{
		Name:   baseFileName,
		Method: zip.Store, // uncompressed
	}
	fh.SetModTime(pk.fr.ModTime())
	fh.SetMode(0644)
	fw, err := zw.CreateHeader(fh)
	check(err)
	check(zw.Flush())
	dataStart := cw.n

	zipMax := pk.s.maxZipBlobSize()
	chunks := pk.chunksRemain
	truncated := false
	chunkWholeHash := blob.NewHash()
	for len(chunks) > 0 {
		dr := chunks[0] // the next chunk to maybe write

		if trunc.Valid() && trunc == dr {
			if approxSize == 0 {
				return errors.New("first blob is too large to pack, once you add the zip overhead")
			}
			truncated = true
			break
		}

		schemaBlobsSave := schemaBlobs
		for _, parent := range pk.schemaParent[dr] {
			if !schemaBlobSeen[parent] {
				schemaBlobSeen[parent] = true
				schemaBlobs = append(schemaBlobs, parent)
				approxSize += int(pk.schemaBlob[parent].Size())
			}
		}

		thisSize := pk.dataSize[dr]
		approxSize += int(thisSize)
		if approxSize+mf.approxSerializedSize()+zipOverhead > zipMax {
			schemaBlobs = schemaBlobsSave // restore it
			truncated = true
			break
		}

		// Copy the data to the zip.
		rc, size, err := pk.src.Fetch(dr)
		check(err)
		if size != thisSize {
			rc.Close()
			return errors.New("unexpected size")
		}
		if n, err := io.Copy(io.MultiWriter(fw, chunkWholeHash), rc); err != nil || n != int64(size) {
			rc.Close()
			return fmt.Errorf("copy to zip = %v, %v; want %v bytes", n, err, size)
		}
		rc.Close()

		dataRefsWritten = append(dataRefsWritten, dr)
		chunks = chunks[1:]
	}
	mf.DataBlobsOrigin = blob.RefFromHash(chunkWholeHash)

	// zipBlobs is where a schema or data blob is relative to the beginning
	// of the zip file.
	var zipBlobs []BlobAndPos

	var dataOffset int64
	for _, br := range dataRefsWritten {
		size := pk.dataSize[br]
		mf.DataBlobs = append(mf.DataBlobs, BlobAndPos{blob.SizedRef{br, size}, dataOffset})

		zipBlobs = append(zipBlobs, BlobAndPos{blob.SizedRef{br, size}, dataStart + dataOffset})
		dataOffset += int64(size)
	}

	for _, br := range schemaBlobs {
		fw, err := zw.CreateHeader(&zip.FileHeader{
			Name:   "camlistore/" + br.String() + ".json",
			Method: zip.Store, // uncompressed
		})
		check(err)
		check(zw.Flush())
		b := pk.schemaBlob[br]
		zipBlobs = append(zipBlobs, BlobAndPos{blob.SizedRef{br, b.Size()}, cw.n})
		rc := b.Open()
		n, err := io.Copy(fw, rc)
		rc.Close()
		check(err)
		if n != int64(b.Size()) {
			return fmt.Errorf("failed to write all of schema blob %v: %n bytes, not wanted %d", br, n, b.Size())
		}
	}

	// Manifest file
	fw, err = zw.Create("camlistore/camlistore-pack-manifest.json")
	check(err)
	enc, err := json.MarshalIndent(mf, "", "  ")
	check(err)
	_, err = fw.Write(enc)
	check(err)
	err = zw.Close()
	check(err)

	if zbuf.Len() > zipMax {
		// We guessed wrong. Back up. Find out how many blobs we went over.
		overage := zbuf.Len() - zipMax
		for i := len(dataRefsWritten) - 1; i >= 0; i-- {
			dr := dataRefsWritten[i]
			if overage <= 0 {
				return needsTruncatedAfterError{dr}
			}
			overage -= int(pk.dataSize[dr])
		}
		return errors.New("file is unpackable; first blob is too big to fit")
	}

	zipRef := blob.SHA1FromBytes(zbuf.Bytes())
	zipSB, err := blobserver.ReceiveNoHash(pk.s.large, zipRef, bytes.NewReader(zbuf.Bytes()))
	if err != nil {
		return err
	}

	pk.zips = append(pk.zips, writtenZip{
		SizedRef: zipSB,
		dataRefs: dataRefsWritten,
	})

	bm := pk.s.meta.BeginBatch()
	for _, zb := range zipBlobs {
		bm.Set(blobMetaPrefix+zb.Ref.String(), fmt.Sprintf("%d l %v %d", zb.Size, zipRef, zb.Offset))
	}
	if err := pk.s.meta.CommitBatch(bm); err != nil {
		return err
	}

	_ = truncated

	// On success, consume the chunks we wrote from pk.chunksRemain.
	pk.chunksRemain = pk.chunksRemain[len(dataRefsWritten):]
	return nil
}

type BlobAndPos struct {
	blob.SizedRef
	Offset int64 `json:"offset"`
}

// Manifest is the JSON description type representing the
// "camlistore/camlistore-pack-manifest.json" file found in a blobpack
// zip file.
type Manifest struct {
	// WholeRef is the blobref of the entire file that this zip is
	// either fully or partially describing.  For files under
	// around 16MB, the WholeRef and DataBlobsOrigin will be
	// the same.
	WholeRef blob.Ref `json:"wholeRef"`

	// WholeSize is the number of bytes in the original file being
	// cut up.
	WholeSize int64 `json:"wholeSize"`

	// WholePartIndex is the chunk number (0-based) of this zip file.
	// If a client has 'n' zip files with the same WholeRef whose
	// WholePartIndexes are contiguous (including 0) and the sum of
	// the DataBlobs equals WholeSize, the client has the entire
	// original file.
	WholePartIndex int `json:"wholePartIndex"`

	// DataBlobsOrigin is the blobref of the contents of the first
	// file in the zip pack file. It is the origin of all the logical data
	// blobs referenced in DataBlobs.
	DataBlobsOrigin blob.Ref `json:"dataBlobsOrigin"`

	// DataBlobs describes all the logical blobs that are
	// concatenated together in the DataBlobsOrigin.
	DataBlobs []BlobAndPos `json:"dataBlobs"`
}

func (mf *Manifest) approxSerializedSize() int {
	// Conservative:
	return 250 + len(mf.DataBlobs)*100
}

type countWriter struct {
	w io.Writer
	n int64
}

func (cw *countWriter) Write(p []byte) (n int, err error) {
	n, err = cw.w.Write(p)
	cw.n += int64(n)
	return
}
