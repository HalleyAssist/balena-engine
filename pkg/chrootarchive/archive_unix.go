//go:build !windows
// +build !windows

package chrootarchive // import "github.com/docker/docker/pkg/chrootarchive"

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/reexec"
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

	cmd := reexec.Command("docker-tar", relSrc, root)

	errBuff := bytes.NewBuffer(nil)
	cmd.Stderr = errBuff

	tarR, tarW := io.Pipe()
	cmd.Stdout = tarW

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, errors.Wrap(err, "error getting options pipe for tar process")
	}

	if err := cmd.Start(); err != nil {
		return nil, errors.Wrap(err, "tar error on re-exec cmd")
	}

	go func() {
		err := cmd.Wait()
		err = errors.Wrapf(err, "error processing tar file: %s", errBuff)
		tarW.CloseWithError(err)
	}()

	if err := json.NewEncoder(stdin).Encode(options); err != nil {
		stdin.Close()
		return nil, errors.Wrap(err, "tar json encode to pipe failed")
	}
	stdin.Close()

	return tarR, nil
}
