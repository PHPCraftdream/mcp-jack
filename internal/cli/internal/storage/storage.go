package storage

import (
	"bytes"
	"encoding/json"
	"io"
	"os"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
)

func ReadPrivate(path string, limit int64) ([]byte, error) {
	if PrivateParent(path) != nil {
		return nil, command.ErrConfig
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || !Owned(before) || before.Size() > limit {
		return nil, command.ErrConfig
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, command.ErrConfig
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, command.ErrConfig
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, command.ErrConfig
	}
	return b, nil
}

func CreateFiles(paths []string, contents [][]byte) error {
	if len(paths) != len(contents) {
		return command.ErrConfig
	}
	files := make([]*os.File, 0, len(paths))
	for _, path := range paths {
		if PrivateParent(path) != nil {
			for i, f := range files {
				_ = f.Close()
				_ = os.Remove(paths[i])
			}
			return command.ErrConfig
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			for i, f := range files {
				_ = f.Close()
				_ = os.Remove(paths[i])
			}
			return command.ErrConfig
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
		return command.ErrConfig
	}
	return nil
}

func Exclusive(path string, data []byte) error {
	return CreateFiles([]string{path}, [][]byte{data})
}

func LockState(path string) (func(), error) {
	if err := Exclusive(path+".owner", []byte("jack owner\n")); err != nil {
		return nil, err
	}
	return func() { _ = os.Remove(path + ".owner") }, nil
}

func DecodeConfig(path string, dst any) error {
	b, err := ReadPrivate(path, 16384)
	if err != nil {
		return err
	}
	if _, err := wire.Object(b); err != nil {
		return command.ErrConfig
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(new(any)) != io.EOF {
		return command.ErrConfig
	}
	return nil
}
