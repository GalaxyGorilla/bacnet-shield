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
// has already been read (open is its tag number); the matching closing tag is
// consumed as well. Nested constructed values must close in order: a mismatched
// closing tag is an error, because accepting it would let a crafted write move
// the parser's cursor and make the policy inspect a different target than the
// device does.
func (r *tagReader) skipValue(open uint8) error {
	stack := []uint8{open}
	for len(stack) > 0 {
		t, err := r.next()
		if err != nil {
			return err
		}
		switch {
		case t.Opening:
			stack = append(stack, t.Number)
		case t.Closing:
			want := stack[len(stack)-1]
			if t.Number != want {
				return fmt.Errorf("bacnet: tag: closing tag %d, want %d", t.Number, want)
			}
			stack = stack[:len(stack)-1]
		}
	}
	return nil
}

// tagEnumerated is the application tag number for an ENUMERATED value. Error
// classes and error codes are the two ENUMERATEDs every Error PDU carries.
const tagEnumerated uint8 = 9

// enumerated decodes an application-tagged ENUMERATED value.
func (t Tag) enumerated() (uint32, error) {
	if t.Context || t.Number != tagEnumerated {
		return 0, fmt.Errorf("bacnet: tag %d is not an application enumerated", t.Number)
	}
	if len(t.Data) > 4 {
		return 0, fmt.Errorf("bacnet: enumerated: %d-byte value", len(t.Data))
	}
	var v uint32
	for _, b := range t.Data {
		v = v<<8 | uint32(b)
	}
	return v, nil
}

// uint decodes a context-tagged unsigned integer (property identifiers and
// array indexes are encoded that way).
func (t Tag) uint() (uint32, error) {
	if !t.Context {
		return 0, fmt.Errorf("bacnet: tag %d is not context tagged", t.Number)
	}
	if len(t.Data) > 4 {
		return 0, fmt.Errorf("bacnet: tag %d: %d-byte unsigned", t.Number, len(t.Data))
	}
	// BACnet encodes unsigned 0 with a zero-length value, so empty data is
	// 0, not a malformed tag. Property identifier 0 (acked-transitions) and
	// array index 0 both use this form.
	var v uint32
	for _, b := range t.Data {
		v = v<<8 | uint32(b)
	}
	return v, nil
}
