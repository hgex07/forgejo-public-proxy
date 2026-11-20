// SPDX-License-Identifier: AGPL-3.0-or-later

package site

import (
	"fmt"
	"time"
)

// Lang is an interface language: message table and date formats.
type Lang struct {
	Code   string
	msgs   map[string]string
	months [12]string
}

// T formats message key with args (fmt verbs). Unknown keys render as the
// key itself so a missing translation is visible but harmless.
func (l *Lang) T(key string, args ...any) string {
	m, ok := l.msgs[key]
	if !ok {
		return key
	}
	if len(args) == 0 {
		return m
	}
	return fmt.Sprintf(m, args...)
}

// Day formats a date (UTC) without time.
func (l *Lang) Day(t time.Time) string {
	t = t.UTC()
	if l.Code == "es" {
		return fmt.Sprintf("%d %s %d", t.Day(), l.months[t.Month()-1], t.Year())
	}
	return fmt.Sprintf("%s %d, %d", l.months[t.Month()-1], t.Day(), t.Year())
}

// DateTime formats a date with time in UTC.
func (l *Lang) DateTime(t time.Time) string {
	return l.Day(t) + " " + t.UTC().Format("15:04") + " UTC"
}

// Languages are the supported interface languages.
var Languages = map[string]*Lang{
	"en": {Code: "en", months: [12]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}, msgs: map[string]string{
		"skip_to_content":      "Skip to content",
		"footer_mirror":        "Read-only mirror. Only selected branches, tags and recent history are published.",
		"repositories":         "Repositories",
		"repository":           "Repository",
		"no_repositories":      "No repositories are published yet.",
		"archived":             "Archived",
		"updated_on":           "Updated %s",
		"tab_code":             "Code",
		"tab_commits":          "Commits",
		"tab_branches":         "Branches",
		"tab_tags":             "Tags",
		"tab_releases":         "Releases",
		"path":                 "Path",
		"name":                 "Name",
		"last_commit":          "Last commit",
		"last_change":          "Last change",
		"about":                "About",
		"no_description":       "No description.",
		"license":              "License",
		"languages":            "Languages",
		"latest_release":       "Latest release",
		"download":             "Download",
		"n_lines":              "%d lines",
		"preview":              "Preview",
		"source":               "Source",
		"raw":                  "Raw",
		"bidi_warning":         "This file contains bidirectional Unicode characters that may display differently than they are stored.",
		"symlink_to":           "Symbolic link to",
		"submodule_at":         "Submodule at commit %s",
		"stored_lfs":           "This file is stored with Git LFS; its content is not published.",
		"binary_file":          "Binary file not shown.",
		"file_too_large":       "File too large to display. Use the Raw link.",
		"empty_file":           "Empty file.",
		"commits_on":           "Commits on %s",
		"pagination":           "Pagination",
		"newer":                "Newer",
		"older":                "Older",
		"older_history_hidden": "Older history is not published.",
		"commit":               "Commit",
		"parent":               "Parent",
		"changes_unknown":      "The changes of this commit are not published (its parent is outside the published history).",
		"n_files_changed":      "%d changed files",
		"binary":               "binary",
		"n_changes_hidden":     "%d more changed files are not published.",
		"diff_binary":          "Binary file changed.",
		"diff_too_large":       "Diff too large to display.",
		"diff_none":            "No content changes.",
		"default":              "default",
		"prerelease":           "Pre-release",
		"no_releases":          "No releases are published.",
		"source_code_zip":      "Source code (zip)",
		"source_code_tar":      "Source code (tar.gz)",
		"not_found":            "Page not found",
		"not_found_text":       "This page does not exist or is not published.",
		"back_home":            "Back to the repository list",
		"dir_not_published":    "(not browsable)",
		"clone":                "Clone",
		"clone_https":          "Clone with HTTPS",
		"clone_note":           "A snapshot of the published files: one commit per branch or tag, without the older history. Commit IDs differ from the original repository.",
	}},
	"es": {Code: "es", months: [12]string{"ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sept", "oct", "nov", "dic"}, msgs: map[string]string{
		"skip_to_content":      "Saltar al contenido",
		"footer_mirror":        "Réplica de solo lectura. Solo se publican algunas ramas, etiquetas y el historial reciente.",
		"repositories":         "Repositorios",
		"repository":           "Repositorio",
		"no_repositories":      "Todavía no hay repositorios publicados.",
		"archived":             "Archivado",
		"updated_on":           "Actualizado el %s",
		"tab_code":             "Código",
		"tab_commits":          "Commits",
		"tab_branches":         "Ramas",
		"tab_tags":             "Etiquetas",
		"tab_releases":         "Versiones",
		"path":                 "Ruta",
		"name":                 "Nombre",
		"last_commit":          "Último commit",
		"last_change":          "Último cambio",
		"about":                "Acerca de",
		"no_description":       "Sin descripción.",
		"license":              "Licencia",
		"languages":            "Lenguajes",
		"latest_release":       "Última versión",
		"download":             "Descargar",
		"n_lines":              "%d líneas",
		"preview":              "Vista previa",
		"source":               "Código fuente",
		"raw":                  "Sin formato",
		"bidi_warning":         "Este archivo contiene caracteres Unicode bidireccionales que pueden mostrarse de forma distinta a como están guardados.",
		"symlink_to":           "Enlace simbólico a",
		"submodule_at":         "Submódulo en el commit %s",
		"stored_lfs":           "Este archivo está guardado con Git LFS; su contenido no se publica.",
		"binary_file":          "Archivo binario no mostrado.",
		"file_too_large":       "Archivo demasiado grande para mostrarlo. Usa el enlace «Sin formato».",
		"empty_file":           "Archivo vacío.",
		"commits_on":           "Commits del %s",
		"pagination":           "Paginación",
		"newer":                "Más recientes",
		"older":                "Más antiguos",
		"older_history_hidden": "El historial más antiguo no se publica.",
		"commit":               "Commit",
		"parent":               "Padre",
		"changes_unknown":      "Los cambios de este commit no se publican (su padre queda fuera del historial publicado).",
		"n_files_changed":      "%d archivos modificados",
		"binary":               "binario",
		"n_changes_hidden":     "Otros %d archivos modificados no se publican.",
		"diff_binary":          "Archivo binario modificado.",
		"diff_too_large":       "Diferencias demasiado grandes para mostrarlas.",
		"diff_none":            "Sin cambios de contenido.",
		"default":              "predeterminada",
		"prerelease":           "Prelanzamiento",
		"no_releases":          "No hay versiones publicadas.",
		"source_code_zip":      "Código fuente (zip)",
		"source_code_tar":      "Código fuente (tar.gz)",
		"not_found":            "Página no encontrada",
		"not_found_text":       "Esta página no existe o no está publicada.",
		"back_home":            "Volver a la lista de repositorios",
		"dir_not_published":    "(no navegable)",
		"clone":                "Clonar",
		"clone_https":          "Clonar con HTTPS",
		"clone_note":           "Una instantánea de los archivos publicados: un commit por rama o etiqueta, sin el historial anterior. Los identificadores de commit no coinciden con los del repositorio original.",
	}},
}

// LangFor returns the language for a config code ("" = en).
func LangFor(code string) *Lang {
	if l, ok := Languages[code]; ok {
		return l
	}
	return Languages["en"]
}
