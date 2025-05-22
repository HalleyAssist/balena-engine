//go:build !windows
// +build !windows

package chrootarchive // import "github.com/docker/docker/pkg/chrootarchive"

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/docker/docker/pkg/archive"
	"github.com/pkg/errors"
)

func invokeUnpack(decompressedArchive io.ReadCloser,
	dest string,
	options *archive.TarOptions, root string) error {

	// This is normally how Windows would unpack the archive, but since
	// we need reduced resources we will unpack the archive in the daemon process
	return archive.Unpack(decompressedArchive, dest, options)
}

func tar() {
	runtime.LockOSThread()
	flag.Parse()

	src := flag.Arg(0)
	var root string
	if len(flag.Args()) > 1 {
		root = flag.Arg(1)
	}

	if root == "" {
		root = src
	}

	if err := realChroot(root); err != nil {
		fatal(err)
	}

	var options archive.TarOptions
	if err := json.NewDecoder(os.Stdin).Decode(&options); err != nil {
		fatal(err)
	}

	rdr, err := archive.TarWithOptions(src, &options)
	if err != nil {
		fatal(err)
	}
	defer rdr.Close()

	if _, err := io.Copy(os.Stdout, rdr); err != nil {
		fatal(err)
	}

	os.Exit(0)
}

func invokePack(srcPath string, options *archive.TarOptions, root string) (io.ReadCloser, error) {
	if root == "" {
		return nil, errors.New("root path must not be empty")
	}

	relSrc, err := filepath.Rel(root, srcPath)
	if err != nil {
		return nil, err
	}
	if relSrc == "." {
		relSrc = "/"
	}
	if relSrc[0] != '/' {
		relSrc = "/" + relSrc
	}

	// make sure we didn't trim a trailing slash with the call to `Rel`
	if strings.HasSuffix(srcPath, "/") && !strings.HasSuffix(relSrc, "/") {
		relSrc += "/"
	}

	if root == "" {
		root = relSrc
	}

	rdr, err := archive.TarWithOptions(relSrc, options)

	return rdr, err
}
