package librsync

import (
	"encoding/binary"
	"fmt"
	"io"
)

type MagicNumber uint32

const (
	DELTA_MAGIC MagicNumber = 0x72730236

	// A signature file with MD4 signatures.
	//
	// Backward compatible with librsync < 1.0, but strongly deprecated because
	// it creates a security vulnerability on files containing partly untrusted
	// data. See <https://github.com/librsync/librsync/issues/5>.
	MD4_SIG_MAGIC MagicNumber = 0x72730136

	// A signature file using the BLAKE2 hash. Supported from librsync 1.0.
	BLAKE2_SIG_MAGIC MagicNumber = 0x72730137
)

func readParam(r io.Reader, size uint8) int64 {
	switch size {
	case 1:
		var tmp uint8
		binary.Read(r, binary.BigEndian, &tmp)
		return int64(tmp)
	case 2:
		var tmp uint16
		binary.Read(r, binary.BigEndian, &tmp)
		return int64(tmp)
	case 4:
		var tmp uint32
		binary.Read(r, binary.BigEndian, &tmp)
		return int64(tmp)
	case 8:
		var tmp int64
		binary.Read(r, binary.BigEndian, &tmp)
		return int64(tmp)
	}
	return 0
}

// CopyN copies n bytes (or until an error) from src to dst.
// It returns the number of bytes copied and the earliest
// error encountered while copying.
// On return, written == n if and only if err == nil.
//
// If dst implements [ReaderFrom], the copy is implemented using it.
func CopyN(dst io.Writer, src io.Reader, n int64, buf []byte) (written int64, err error) {
	written, err = io.CopyBuffer(dst, io.LimitReader(src, n), buf)
	if written == n {
		return n, nil
	}
	if written < n && err == nil {
		// src stopped early; must have been EOF.
		err = io.EOF
	}
	return
}

func Patch(base io.ReadSeeker, delta io.Reader, out io.Writer) error {
	var magic MagicNumber

	err := binary.Read(delta, binary.BigEndian, &magic)
	if err != nil {
		return err
	}

	if magic != DELTA_MAGIC {
		return fmt.Errorf("Got magic number %x rather than expected value %x", magic, DELTA_MAGIC)
	}

	buf := make([]byte, 32*1024) // Buffer for CopyN

	var streamPos int64 = -1
	for {
		var op Op
		err := binary.Read(delta, binary.BigEndian, &op)
		if err != nil {
			return err
		}
		cmd := op2cmd[op]

		var param1, param2 int64

		if cmd.Len1 == 0 {
			param1 = int64(cmd.Immediate)
		} else {
			param1 = readParam(delta, cmd.Len1)
			param2 = readParam(delta, cmd.Len2)
		}

		switch cmd.Kind {
		default:
			err = fmt.Errorf("Bogus command %x", cmd.Kind)
		case KIND_LITERAL:
			_, err = CopyN(out, delta, param1, buf)
		case KIND_COPY:
			if streamPos == -1 || param1 != streamPos {
				streamPos, err = base.Seek(param1, io.SeekStart)
				if err != nil {
					return fmt.Errorf("Seek to %d failed: %w", param1, err)
				}
			}
			param2, err = CopyN(out, base, param2, buf)
			streamPos += param2
		case KIND_END:
			return nil
		}

		if err != nil {
			return fmt.Errorf("Error while processing command %x: %w", cmd.Kind, err)
		}
	}
}
