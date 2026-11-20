// SPDX-License-Identifier: AGPL-3.0-or-later

package site

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io/fs"
	"time"

	"fpp/internal/policy"
)

// archiver writes a ref's source archives straight from the publish set, so
// they contain exactly the published files (no git archive, no attributes,
// no export-subst). Output is deterministic for a given publish set.
type archiver struct {
	prefix string
	mtime  time.Time
	zf, tf *countingFile
	zw     *zip.Writer
	gz     *gzip.Writer
	tw     *tar.Writer
}

// archiveEpoch is used when the ref's commit date is not published.
var archiveEpoch = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

func newArchiver(w *writer, zipPath, tarPath, prefix string, mtime time.Time) (*archiver, error) {
	if mtime.IsZero() || mtime.Before(archiveEpoch) {
		mtime = archiveEpoch
	}
	a := &archiver{prefix: prefix, mtime: mtime.UTC()}
	var err error
	if a.zf, err = w.create(zipPath); err != nil {
		return nil, err
	}
	if a.tf, err = w.create(tarPath); err != nil {
		a.zf.Close()
		return nil, err
	}
	a.zw = zip.NewWriter(a.zf)
	a.gz, _ = gzip.NewWriterLevel(a.tf, gzip.BestCompression)
	a.gz.ModTime = a.mtime
	a.tw = tar.NewWriter(a.gz)
	return a, nil
}

func (a *archiver) add(f policy.File, data []byte) error {
	name := a.prefix + f.Path
	var mode fs.FileMode = 0o644
	switch f.Kind {
	case policy.Executable:
		mode = 0o755
	case policy.Symlink:
		mode = fs.ModeSymlink | 0o777
	case policy.Submodule:
		return nil
	}
	zh := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: a.mtime}
	zh.SetMode(mode)
	zw, err := a.zw.CreateHeader(zh)
	if err != nil {
		return err
	}
	if _, err := zw.Write(data); err != nil {
		return err
	}
	th := &tar.Header{Name: name, Mode: int64(mode.Perm()), ModTime: a.mtime, Format: tar.FormatPAX,
		Uname: "root", Gname: "root"}
	if f.Kind == policy.Symlink {
		th.Typeflag = tar.TypeSymlink
		th.Linkname = string(data)
	} else {
		th.Typeflag = tar.TypeReg
		th.Size = int64(len(data))
	}
	if err := a.tw.WriteHeader(th); err != nil {
		return err
	}
	if f.Kind != policy.Symlink {
		_, err = a.tw.Write(data)
	}
	return err
}

func (a *archiver) close() error {
	errs := []error{a.zw.Close(), a.zf.Close(), a.tw.Close(), a.gz.Close(), a.tf.Close()}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
