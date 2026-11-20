// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"context"
	"errors"
	"fmt"
)

// MaxBatchBytes bounds how much blob data ReadBlobs buffers at once.
const MaxBatchBytes = 64 << 20

func (r *Repo) indexBlobs() {
	r.blobs = map[string]bool{}
	for _, ref := range r.Refs {
		for _, f := range ref.Files {
			if f.Kind != Submodule {
				r.blobs[f.OID] = true
			}
		}
	}
	for _, c := range r.Commits {
		for _, ch := range c.Changes {
			if ch.OldBlob != "" {
				r.blobs[ch.OldBlob] = true
			}
			if ch.NewBlob != "" {
				r.blobs[ch.NewBlob] = true
			}
		}
	}
}

// ReadBlobs calls fn with the contents of each blob, in order. Only blobs that
// are part of the publish set can be read (I3): asking for anything else is
// an error. Each blob must be at most maxSize bytes. fn must not retain data
// after it returns.
func (r *Repo) ReadBlobs(ctx context.Context, oids []string, maxSize int64, fn func(oid string, data []byte) error) error {
	for _, o := range oids {
		if !r.blobs[o] {
			return fmt.Errorf("policy: blob %.12s is not in the publish set", o)
		}
	}
	if len(oids) == 0 {
		return nil
	}
	if r.git == nil {
		return errors.New("policy: repo has no git store")
	}
	infos, err := r.git.ObjectSizes(ctx, oids)
	if err != nil {
		return err
	}
	for start := 0; start < len(infos); {
		var batch []string
		var total int64
		end := start
		for ; end < len(infos); end++ {
			in := infos[end]
			if in.Type != "blob" {
				return fmt.Errorf("policy: object %.12s is a %s, not a blob", in.OID, in.Type)
			}
			if in.Size > maxSize {
				return fmt.Errorf("policy: blob %.12s is %d bytes, over the %d byte cap", in.OID, in.Size, maxSize)
			}
			if len(batch) > 0 && total+in.Size > MaxBatchBytes {
				break
			}
			batch = append(batch, in.OID)
			total += in.Size
		}
		objs, err := r.git.ReadObjects(ctx, batch, maxSize)
		if err != nil {
			return err
		}
		for _, o := range objs {
			if err := fn(o.OID, o.Data); err != nil {
				return err
			}
		}
		start = end
	}
	return nil
}

// BlobSizes returns the size of each published blob (same access rule as
// ReadBlobs).
func (r *Repo) BlobSizes(ctx context.Context, oids []string) (map[string]int64, error) {
	for _, o := range oids {
		if !r.blobs[o] {
			return nil, fmt.Errorf("policy: blob %.12s is not in the publish set", o)
		}
	}
	out := map[string]int64{}
	if len(oids) == 0 {
		return out, nil
	}
	if r.git == nil {
		return nil, errors.New("policy: repo has no git store")
	}
	infos, err := r.git.ObjectSizes(ctx, oids)
	if err != nil {
		return nil, err
	}
	for _, in := range infos {
		out[in.OID] = in.Size
	}
	return out, nil
}
