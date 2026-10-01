package mkcp

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/metacubex/mihomo/common/pool"
)

type packetReader struct {
	security cipher.AEAD
	header   packetHeader
}

func (r packetReader) read(b []byte) []segment {
	if r.header != nil {
		headerSize := r.header.size()
		if len(b) <= headerSize {
			return nil
		}
		b = b[headerSize:]
	}
	if r.security != nil {
		nonceSize := r.security.NonceSize()
		overhead := r.security.Overhead()
		if len(b) <= nonceSize+overhead {
			return nil
		}
		out, err := r.security.Open(b[nonceSize:nonceSize], b[:nonceSize], b[nonceSize:], nil)
		if err != nil {
			return nil
		}
		b = out
	}
	var segments []segment
	for len(b) > 0 {
		seg, extra := readSegment(b)
		if seg == nil {
			break
		}
		segments = append(segments, seg)
		b = extra
	}
	return segments
}

type packetWriter struct {
	security cipher.AEAD
	header   packetHeader
	writer   io.Writer
}

func (w packetWriter) overhead() int {
	if w.security == nil {
		if w.header == nil {
			return 0
		}
		return w.header.size()
	}
	overhead := w.security.Overhead()
	if w.header != nil {
		overhead += w.header.size()
	}
	return overhead
}

func (w packetWriter) writeSegment(seg segment) error {
	payload := pool.Get(seg.byteSize())
	defer pool.Put(payload)
	seg.serialize(payload)

	headerSize := 0
	if w.header != nil {
		headerSize = w.header.size()
	}

	nonceSize := 0
	if w.security != nil {
		nonceSize = w.security.NonceSize()
	}
	// simpleAuthenticator needs up to three padding bytes while encoding.
	// Keep plaintext separate: its Seal implementation prepends its header.
	buffer := pool.Get(headerSize + nonceSize + len(payload) + w.securityOverhead() + 3)
	defer pool.Put(buffer)
	out := buffer[:headerSize]
	if headerSize > 0 {
		w.header.serialize(out[:headerSize])
	}

	if w.security != nil {
		out = out[:headerSize+nonceSize]
		if nonceSize > 0 {
			_, _ = rand.Read(out[headerSize : headerSize+nonceSize])
		}
		sealed := w.security.Seal(out[headerSize+nonceSize:headerSize+nonceSize], out[headerSize:headerSize+nonceSize], payload, nil)
		out = append(out[:headerSize+nonceSize], sealed...)
	} else {
		out = append(out, payload...)
	}

	_, err := w.writer.Write(out)
	return err
}

func (w packetWriter) securityOverhead() int {
	if w.security == nil {
		return 0
	}
	return w.security.Overhead()
}
