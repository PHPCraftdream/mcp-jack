package stdio

import (
	"io"
)

type IO struct {
	In  io.ReadCloser
	Out io.WriteCloser
	Err io.Writer
}
