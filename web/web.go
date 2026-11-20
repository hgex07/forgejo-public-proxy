// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web holds the site templates and static assets, embedded in the
// fpp binary.
package web

import "embed"

// Templates are html/template files: base.html and partials.html are shared;
// every other file is one page type defining "title" and "content".
//
//go:embed templates/*.html
var Templates embed.FS

// Static assets are published under /_static/ with a content hash in the
// file name.
//
//go:embed static/*
var Static embed.FS
