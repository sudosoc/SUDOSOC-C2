//go:build !cgo_sqlite && !go_sqlite && !wasm_sqlite

package db

import (
	"gorm.io/gorm"

	"github.com/sudosoc/SUDOSOC-C2/server/configs"
)

// sqliteClient stub — satisfies the sqliteClient reference in sql.go when
// no explicit sqlite build tag is provided. Panics at runtime with a helpful
// message directing the user to pick a sqlite backend build tag.
func sqliteClient(dbConfig *configs.DatabaseConfig) *gorm.DB {
	panic("sqliteClient: no sqlite backend compiled in. " +
		"Rebuild with -tags cgo_sqlite, go_sqlite, or wasm_sqlite.")
}
