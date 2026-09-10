package webassets

import (
	"embed"
	"io/fs"
)

//go:embed all:dist fallback/index.html
var embedded embed.FS

func FS() fs.FS {
	root := "dist"
	if _, e := fs.Stat(embedded, "dist/index.html"); e != nil {
		root = "fallback"
	}
	f, e := fs.Sub(embedded, root)
	if e != nil {
		panic(e)
	}
	return f
}
