package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
)

func readPrivate(path string, limit int64) ([]byte, error) {
	if privateParent(path) != nil {
		return nil, errConfig
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || !owned(before) || before.Size() > limit {
		return nil, errConfig
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errConfig
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errConfig
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errConfig
	}
	return b, nil
}

func createFiles(paths []string, contents [][]byte) error {
	if len(paths) != len(contents) {
		return errConfig
	}
	files := make([]*os.File, 0, len(paths))
	for _, path := range paths {
		if privateParent(path) != nil {
			for i, f := range files {
				_ = f.Close()
				_ = os.Remove(paths[i])
			}
			return errConfig
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			for i, f := range files {
				_ = f.Close()
				_ = os.Remove(paths[i])
			}
			return errConfig
		}
		files = append(files, f)
	}
	ok := true
	for i, f := range files {
		if n, err := f.Write(contents[i]); err != nil || n != len(contents[i]) {
			ok = false
		}
		if f.Sync() != nil {
			ok = false
		}
		if f.Close() != nil {
			ok = false
		}
	}
	if !ok {
		return errConfig
	}
	return nil
}

func exclusive(path string, data []byte) error {
	return createFiles([]string{path}, [][]byte{data})
}

func lockState(path string) (func(), error) {
	if err := exclusive(path+".owner", []byte("jack owner\n")); err != nil {
		return nil, err
	}
	return func() { _ = os.Remove(path + ".owner") }, nil
}

func decodeConfig(path string, dst any) error {
	b, err := readPrivate(path, 16384)
	if err != nil {
		return err
	}
	if _, err := object(b); err != nil {
		return errConfig
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(new(any)) != io.EOF {
		return errConfig
	}
	return nil
}
