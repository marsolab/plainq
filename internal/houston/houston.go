package houston

import (
	"embed"
	"io/fs"
)

//go:embed all:ui/dist
var bundle embed.FS

func Bundle() fs.FS {
	sub, err := fs.Sub(bundle, "ui/dist")
	if err != nil {
		panic(err)
	}

	return sub
}
