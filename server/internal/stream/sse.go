package stream

import (
	"bytes"
	"errors"
	"strings"
)

// errEventTooLarge reports a handler event whose data value exceeds the frame
// cap (2.17); the session turns it into the 2.18 transport signal.
var errEventTooLarge = errors.New("stream: handler event exceeds the frame cap")

// splitter turns the bytes of a handler's event stream into the data values of
// its complete events. It accepts LF, CRLF and a lone CR (2.14), drops
// comments, event names, id and retry fields and unknown fields (2.11-2.13),
// joins the data lines of one event with a single LF and therefore normalises
// a raw CR or CRLF inside the data to LF (2.10).
type splitter struct {
	line          []byte
	skipLF        bool
	data          []string
	hasData       bool
	size          int64
	limit         int64
	lineIsData    bool
	lineIsComment bool
	lineValueSize int64
	// exceeded is set once limit was passed, so the caller stops retaining.
	exceeded bool
}

// feed consumes chunk and calls emit for every completed event that carried at
// least one data line. A trailing unterminated line is kept for the next feed.
// limit bounds the bytes retained for the event under construction; when it is
// passed the event is dropped and errEventTooLarge returned (2.17). A limit of
// zero or less keeps no bound.
func (s *splitter) feed(chunk []byte, limit int64, emit func(data string) error) error {
	s.limit = limit
	for _, b := range chunk {
		if s.skipLF {
			s.skipLF = false
			if b == '\n' {
				continue
			}
		}
		if b == '\n' || b == '\r' {
			s.skipLF = b == '\r'
			if err := s.endLine(emit); err != nil {
				return err
			}
			continue
		}
		if s.lineIsComment {
			continue
		}
		if len(s.line) == 0 && b == ':' {
			s.lineIsComment = true
			continue
		}
		s.line = append(s.line, b)
		if s.lineIsData {
			if len(s.line) == 6 && b == ' ' {
				continue
			}
			if len(s.line) >= 6 {
				s.lineValueSize++
				if s.hasData {
					if s.overLimit(s.size + 1 + s.lineValueSize) {
						return errEventTooLarge
					}
				} else if s.overLimit(s.lineValueSize) {
					return errEventTooLarge
				}
			}
			continue
		}
		if len(s.line) <= len("data:") && string(s.line) == "data:"[:len(s.line)] {
			if string(s.line) == "data:" {
				s.lineIsData = true
			}
			continue
		}
	}
	return nil
}

// endLine finishes the current line and closes the event on a blank line.
func (s *splitter) endLine(emit func(data string) error) error {
	line := s.line
	isData, isComment := s.lineIsData, s.lineIsComment
	s.line = nil
	s.lineIsData = false
	s.lineIsComment = false
	s.lineValueSize = 0
	if len(line) == 0 && !isComment {
		if !s.hasData {
			s.resetEvent()
			return nil
		}
		data := strings.Join(s.data, "\n")
		s.resetEvent()
		return emit(data)
	}
	if isComment || (len(line) > 0 && line[0] == ':') {
		return nil
	}
	name := line
	value := ""
	if i := bytes.IndexByte(line, ':'); i >= 0 {
		name = line[:i]
		value = strings.TrimPrefix(string(line[i+1:]), " ") // one leading SP only
	}
	if isData || string(name) == "data" {
		if s.hasData {
			s.size++
		}
		s.data = append(s.data, value)
		s.hasData = true
		s.size += int64(len(value))
		if s.overLimit(s.size) {
			return errEventTooLarge
		}
	}
	return nil
}

func (s *splitter) resetEvent() {
	s.data = nil
	s.hasData = false
	s.size = 0
}

// overLimit reports whether the event outgrew the budget and drops what was
// retained of it.
func (s *splitter) overLimit(size int64) bool {
	if s.limit <= 0 || size <= s.limit {
		return false
	}
	s.exceeded = true
	s.line = nil
	s.data = nil
	s.hasData = false
	return true
}

// reset discards the unfinished line and event.
func (s *splitter) reset() {
	s.line = nil
	s.skipLF = false
	s.data = nil
	s.hasData = false
	s.size = 0
	s.limit = 0
	s.lineIsData = false
	s.lineIsComment = false
	s.lineValueSize = 0
	s.exceeded = false
}
