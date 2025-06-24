package tarsplitutils

import (
	"fmt"
	"io"
	"io/ioutil"
	"sort"

	"github.com/vbatts/tar-split/tar/storage"
)

func min(x, y int64) int64 {
	if x < y {
		return x
	}
	return y
}

func max(x, y int) int {
	if x < y {
		return y
	}
	return x
}

type ratState struct {
	lastEntry string
	lastFh    io.ReadCloser
	lastPos   int64
}

type randomAccessTarStream struct {
	entries      storage.Entries
	entryOffsets []int64
	fg           storage.FileGetter
	state        *ratState
}

func (self randomAccessTarStream) ReadAt(p []byte, off int64) (int, error) {
	// Find the first entry that we're interested in
	firstEntry := sort.Search(len(self.entryOffsets), func(i int) bool { return self.entryOffsets[i] > off }) - 1

	// The cursor will most likely be negative the first time. This signifies
	// that we need to read some data first before starting to fill the buffer
	// n = -ve position from start of the entry
	n := self.entryOffsets[firstEntry] - off

	for _, entry := range self.entries[firstEntry:] {
		if n >= int64(len(p)) {
			break
		}

		switch entry.Type {
		case storage.SegmentType:
			if self.state.lastEntry != "" {
				self.state.lastFh.Close()
				self.state.lastFh = nil
				self.state.lastEntry = ""
			}

			payload := entry.Payload
			if n < 0 {
				payload = payload[-n:]
				n = 0
			}

			n += int64(copy(p[n:], payload))
		case storage.FileType:
			if entry.Size == 0 {
				continue
			}

			var fh io.ReadCloser
			var err error

			entryName := entry.GetName()
			if self.state.lastEntry == entryName {
				fh = self.state.lastFh
				if n >= 0 {
					if seeker, ok := fh.(io.Seeker); ok {
						seeker.Seek(0, io.SeekStart)
						self.state.lastPos = 0
					} else {
						return 0, fmt.Errorf("Cannot seek in file %s, which is not a seeker", entryName)
					}
				}
			} else {
				if self.state.lastEntry != "" {
					self.state.lastFh.Close()
					self.state.lastFh = nil
					self.state.lastEntry = ""
				}
				fh, err = self.fg.Get(entryName)
				if err != nil {
					return 0, err
				}

				if _, ok := fh.(io.Seeker); ok {
					self.state.lastEntry = entryName
					self.state.lastFh = fh
					self.state.lastPos = 0
				}
			}

			end := min(n+entry.Size, int64(len(p)))

			if n < 0 {
				if seeker, ok := fh.(io.Seeker); ok {
					n = -n
					if self.state.lastPos != n {
						self.state.lastPos = n
						if _, err := seeker.Seek(n, io.SeekStart); err != nil {
							return 0, err
						}
					}
				} else {
					if _, err := io.CopyN(ioutil.Discard, fh, -n); err != nil {
						return 0, err
					}
				}
				n = 0
			}

			_, err = io.ReadFull(fh, p[n:end])

			written := end - n
			n += written
			self.state.lastPos += written
			if err != nil {
				return 0, fmt.Errorf("Error reading file %s: %w", entryName, err)
			}
		default:
			return 0, fmt.Errorf("Unknown tar-split entry type: %v", entry.Type)
		}
	}

	return len(p), nil
}

func (self randomAccessTarStream) Close() {
	if self.state.lastEntry != "" {
		self.state.lastFh.Close()
		self.state.lastFh = nil
		self.state.lastEntry = ""
	}
}

func NewRandomAccessTarStream(fg storage.FileGetter, up storage.Unpacker) (io.ReadSeeker, randomAccessTarStream, error) {
	stream := randomAccessTarStream{
		fg:    fg,
		state: &ratState{},
	}

	size := int64(0)
	for {
		entry, err := up.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, stream, err
		}

		stream.entryOffsets = append(stream.entryOffsets, size)
		stream.entries = append(stream.entries, *entry)

		switch entry.Type {
		case storage.SegmentType:
			size += int64(len(entry.Payload))
		case storage.FileType:
			size += entry.Size
		}
	}

	// Push ending offset. This is because when we binary search we search for
	// the offset that is above the target and then we move one step back.
	// See implementation of ReadAt()
	stream.entryOffsets = append(stream.entryOffsets, size)

	return io.NewSectionReader(stream, 0, size), stream, nil
}
