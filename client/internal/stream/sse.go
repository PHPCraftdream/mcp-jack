package stream

import "bytes"

// bom is the U+FEFF byte order mark ignored once at the very start of the body
// (2.14).
var bom = []byte{0xef, 0xbb, 0xbf}

// field is one SSE field line (2.10).
type field struct {
	name  string
	value []byte
}

// event is one complete SSE event: its field lines and the index of the byte
// that completed its terminating blank line, counted in body bytes after the
// BOM was stripped (2.6, 4.5; the reference maps end-1 to an arrival time).
type event struct {
	fields []field
	end    int
}

// sseParser turns body chunks into complete SSE events (2.6-2.14). It keeps its
// partial state across feeds and accepts any split. It bounds the bytes it
// retains: once one event grows past the budget it sets exceeded and drops its
// field lines, so a hostile body cannot exhaust memory (2.17).
type sseParser struct {
	decided   bool
	prefix    []byte
	skipped   int // BOM bytes stripped from the stream
	offset    int // bytes consumed from the body, the stripped BOM included
	line      []byte
	pendingCR bool
	fields    []field
	size      int64 // bytes retained for the event being assembled
	limit     int64
	exceeded  bool
	emit      func(event) error // the last feed's sink, so reset can end a lone CR
}

// newSSEParser returns a parser that retains at most limit bytes per event;
// limit <= 0 means no budget.
func newSSEParser(limit int64) *sseParser { return &sseParser{limit: limit} }

// feed consumes one body chunk and emits every event it completes, in order.
// An error from emit stops the feed and is returned.
func (p *sseParser) feed(chunk []byte, emit func(event) error) error {
	p.emit = emit
	for _, b := range chunk {
		if !p.decided {
			p.prefix = append(p.prefix, b)
			// 2.14: keep buffering while the bytes so far are a BOM prefix.
			if len(p.prefix) < len(bom) && bytes.Equal(p.prefix, bom[:len(p.prefix)]) {
				p.offset++
				continue
			}
			p.decided = true
			body := p.prefix
			p.prefix = nil
			if bytes.Equal(body, bom) {
				p.skipped = len(bom)
				p.offset++
				continue
			}
			for _, pb := range body {
				if err := p.put(pb, emit); err != nil {
					return err
				}
			}
			continue
		}
		if err := p.put(b, emit); err != nil {
			return err
		}
	}
	return nil
}

// put advances the line machine by one body byte; p.offset is the byte's index
// in the unstripped body.
func (p *sseParser) put(b byte, emit func(event) error) error {
	if p.exceeded {
		// Stop retaining: the verifier aborts on the first such feed.
		p.offset++
		return nil
	}
	if p.pendingCR {
		// The pending CR was a lone terminator unless this byte is its LF.
		p.pendingCR = false
		p.offset++ // the resolved CR now counts
		if b == '\n' {
			end := p.offset - p.skipped // CRLF completes at this LF
			p.offset++
			return p.endLine(end, emit)
		}
		if err := p.endLine(p.offset-1-p.skipped, emit); err != nil {
			return err
		}
		if p.exceeded {
			return nil
		}
	}
	switch b {
	case '\r':
		// Do not end the line yet: the next byte tells a lone CR from a CRLF.
		p.pendingCR = true
		p.add(1)
	case '\n':
		end := p.offset - p.skipped
		p.offset++
		return p.endLine(end, emit)
	default:
		p.line = append(p.line, b)
		p.add(1)
		p.offset++
	}
	return nil
}

// endLine finishes the buffered line; end is the stripped index of the byte
// that terminated it.
func (p *sseParser) endLine(end int, emit func(event) error) error {
	line := p.line
	p.line = nil
	if p.exceeded {
		return nil
	}
	if len(line) == 0 {
		// A blank line closes the event only after a field line.
		if len(p.fields) == 0 {
			p.size = 0
			return nil
		}
		ev := event{fields: p.fields, end: end}
		p.fields = nil
		p.size = 0
		return emit(ev)
	}
	if line[0] == ':' {
		return nil // 2.12: a comment belongs to no event
	}
	name := line
	var value []byte
	if i := bytes.IndexByte(line, ':'); i >= 0 {
		name = line[:i]
		value = line[i+1:]
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:] // one leading SP only
		}
	}
	p.fields = append(p.fields, field{name: string(name), value: append([]byte(nil), value...)})
	return nil
}

// add charges n retained bytes and stops retaining once the budget is passed.
func (p *sseParser) add(n int64) {
	p.size += n
	if p.limit > 0 && p.size > p.limit && !p.exceeded {
		p.exceeded = true
		p.line = nil
		p.fields = nil
	}
}

// reset discards the unfinished line and event, but first ends a pending lone
// CR, which did terminate its line and possibly its event (2.14).
func (p *sseParser) reset() {
	if p.pendingCR {
		p.pendingCR = false
		end := p.offset - p.skipped
		p.offset++
		if !p.exceeded && p.emit != nil {
			_ = p.endLine(end, p.emit) // any error is already recorded by emit
		}
	}
	p.line = nil
	p.fields = nil
	p.size = 0
	p.pendingCR = false
	p.emit = nil
}

// stripped returns the number of body bytes consumed after the BOM was
// stripped; it is the length of the offset space Arrival indexes.
func (p *sseParser) stripped() int { return p.offset - p.skipped }
