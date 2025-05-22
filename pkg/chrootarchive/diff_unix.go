//go:build !windows
// +build !windows

package chrootarchive // import "github.com/docker/docker/pkg/chrootarchive"

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/sys"
	"github.com/docker/docker/pkg/archive"
)

type applyLayerResponse struct {
	LayerSize int64 `json:"layerSize"`
}

// applyLayerHandler parses a diff in the standard layer format from `layer`, and
// applies it to the directory `dest`. Returns the size in bytes of the
// contents of the layer.
func applyLayerHandler(dest string, layer io.Reader, options *archive.TarOptions, decompress bool) (size int64, err error) {
	var tmpDir string

	dest = filepath.Clean(dest)
	if decompress {
		decompressed, err := archive.DecompressStream(layer)
		if err != nil {
			return 0, err
		}
		defer decompressed.Close()

		layer = decompressed
	}
	if options == nil {
		options = &archive.TarOptions{}
		if sys.RunningInUserNS() {
			options.InUserNS = true
		}
	}
	if options.ExcludePatterns == nil {
		options.ExcludePatterns = []string{}
	}

	if tmpDir, err = ioutil.TempDir("/", "temp-docker-extract"); err != nil {
		fatal(err)
	}

	os.Setenv("TMPDIR", tmpDir)
	size, err = archive.UnpackLayer("/", os.Stdin, options)
	os.RemoveAll(tmpDir)
	if err != nil {
		fatal(err)
	}

	return size, err
}
