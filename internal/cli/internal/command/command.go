package command

import (
	"errors"
	"flag"
	"io"
	"time"
)

var ErrConfig = errors.New("invalid configuration or private storage")
var ErrProtocol = errors.New("unsupported or invalid protocol message")
var ErrRemote = errors.New("remote call failed; no retry performed")

func Flags(name string, args []string, names ...string) (map[string]string, error) {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	values := make(map[string]*string)
	for _, name := range names {
		values[name] = f.String(name, "", "")
	}
	if f.Parse(args) != nil || f.NArg() != 0 {
		return nil, ErrConfig
	}
	out := make(map[string]string)
	for name, value := range values {
		if *value == "" {
			return nil, ErrConfig
		}
		out[name] = *value
	}
	return out, nil
}

func CallDuration(ms int) (time.Duration, error) {
	if ms < 100 || ms > 30000 {
		return 0, ErrConfig
	}
	return time.Duration(ms) * time.Millisecond, nil
}
