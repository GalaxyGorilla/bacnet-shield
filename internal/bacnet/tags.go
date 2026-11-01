package bacnet

import "fmt"

// Tag is one decoded BACnet tag. The encoding is shared by application
// values and context-tagged service parameters; only the fields that apply
// to the tag class are set.
type Tag struct {
	Number  uint8
	Context bool
	Opening bool
	Closing bool
	Boolean bool // application BOOLEAN value (carried in the L/V/T field)
	Data    []byte
}

// tagReader walks a tag stream. Every read is bounds-checked: service
// payloads come straight off the wire and a truncated write must be denied,
// not panic the proxy.
type tagReader struct {
	b []byte
	i int
}

func (r *tagReader) next() (Tag, error) {
	if r.i >= len(r.b) {
		return Tag{}, fmt.Errorf("bacnet: tag: truncated")
	}
	initial := r.b[r.i]
	r.i++
	t := Tag{Context: initial&0x08 != 0}
	num := initial >> 4
	if num == 0x0F {
		if r.i >= len(r.b) {
			return Tag{}, fmt.Errorf("bacnet: tag: extended tag number missing")
		}
		num = r.b[r.i]
		r.i++
	}
	t.Number = num

	lvt := initial & 0x07
	switch lvt {
	case 5:
		if r.i >= len(r.b) {
			return Tag{}, fmt.Errorf("bacnet: tag: extended length missing")
		}
		n := r.b[r.i]
		r.i++
		length := 0
		switch n {
		case 254:
			if len(r.b) < r.i+2 {
				return Tag{}, fmt.Errorf("bacnet: tag: 16-bit length missing")
			}
			length = int(r.b[r.i])<<8 | int(r.b[r.i+1])
			r.i += 2
		case 255:
			if len(r.b) < r.i+4 {
				return Tag{}, fmt.Errorf("bacnet: tag: 32-bit length missing")
			}
			length = int(r.b[r.i])<<24 | int(r.b[r.i+1])<<16 | int(r.b[r.i+2])<<8 | int(r.b[r.i+3])
			r.i += 4
		default:
			length = int(n)
		}
		if length < 0 || len(r.b) < r.i+length {
			return Tag{}, fmt.Errorf("bacnet: tag: %d-byte value past end", length)
		}
		t.Data = r.b[r.i : r.i+length]
		r.i += length
	case 6:
		t.Opening = true
	case 7:
		t.Closing = true
	default:
		// L/V/T 0..4 is a literal length. An application BOOLEAN and NULL
		// carry their value in the tag itself and have no data octets.
		if !t.Context && (t.Number == 0 || t.Number == 1) {
			t.Boolean = lvt == 1
			return t, nil
		}
		if len(r.b) < r.i+int(lvt) {
			return Tag{}, fmt.Errorf("bacnet: tag: %d-byte value past end", lvt)
		}
		t.Data = r.b[r.i : r.i+int(lvt)]
		r.i += int(lvt)
	}
	return t, nil
}

// skipValue consumes the remainder of one constructed value. The opening tag
// has already been read; the matching closing tag is consumed as well.
func (r *tagReader) skipValue() error {
	depth := 1
	for depth > 0 {
		t, err := r.next()
		if err != nil {
			return err
		}
		switch {
		case t.Opening:
			depth++
		case t.Closing:
			depth--
		}
	}
	return nil
}

// uint decodes a context-tagged unsigned integer (property identifiers and
// array indexes are encoded that way).
func (t Tag) uint() (uint32, error) {
	if !t.Context {
		return 0, fmt.Errorf("bacnet: tag %d is not context tagged", t.Number)
	}
	if len(t.Data) == 0 || len(t.Data) > 4 {
		return 0, fmt.Errorf("bacnet: tag %d: %d-byte unsigned", t.Number, len(t.Data))
	}
	var v uint32
	for _, b := range t.Data {
		v = v<<8 | uint32(b)
	}
	return v, nil
}
