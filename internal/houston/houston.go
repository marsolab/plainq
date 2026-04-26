package houston

import (
	"errors"
	"io/fs"
	"os"
)

func Bundle() fs.FS {
	// Use local filesystem for UI files.
	if _, err := os.Stat("ui/dist"); err == nil {
		return os.DirFS("ui/dist")
	}

	panic(errors.New("unable to find ui/dist folder"))
}
