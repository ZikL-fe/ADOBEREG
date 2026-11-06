package mail

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"

	"golang.org/x/net/html/charset"
)

type parsed struct {
	Subject     string
	From        string
	ReceivedAt  time.Time
	ContentType string
	Body        string
}

func parseRFC822(raw []byte) (parsed, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return parsed{}, err
	}
	out := parsed{
		Subject: decodeHeader(msg.Header.Get("Subject")),
		From:    decodeHeader(msg.Header.Get("From")),
	}
	if when, err := msg.Header.Date(); err == nil {
		out.ReceivedAt = when.UTC()
	}
	plain, html := "", ""
	collect(msg.Header.Get("Content-Type"), msg.Header.Get("Content-Transfer-Encoding"), msg.Body, &plain, &html)
	if strings.TrimSpace(html) != "" {
		out.ContentType = "html"
		out.Body = html
	} else {
		out.ContentType = "text"
		out.Body = plain
	}
	return out, nil
}

func collect(contentType, encoding string, body io.Reader, plain, html *string) {
	media, params, err := mime.ParseMediaType(contentType)
	if err != nil || media == "" {
		media = "text/plain"
	}
	if strings.HasPrefix(media, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return
		}
		reader := multipart.NewReader(decodeTransfer(body, encoding), boundary)
		for {
			part, err := reader.NextPart()
			if err != nil {
				return
			}
			collect(part.Header.Get("Content-Type"), part.Header.Get("Content-Transfer-Encoding"), part, plain, html)
		}
	}
	data, err := io.ReadAll(io.LimitReader(decodeTransfer(body, encoding), 512<<10))
	if err != nil || len(data) == 0 {
		return
	}
	decoded := data
	if reader, err := charset.NewReader(bytes.NewReader(data), contentType); err == nil {
		if text, err := io.ReadAll(io.LimitReader(reader, 512<<10)); err == nil && len(text) > 0 {
			decoded = text
		}
	}
	text := strings.TrimSpace(string(decoded))
	if strings.Contains(media, "html") && *html == "" {
		*html = text
		return
	}
	if *plain == "" {
		*plain = text
	}
}

func decodeTransfer(r io.Reader, encoding string) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, stripNewlines{r})
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	default:
		return r
	}
}

type stripNewlines struct{ io.Reader }

func (s stripNewlines) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	tmp := make([]byte, len(p))
	for {
		n, err := s.Reader.Read(tmp)
		kept := 0
		for _, b := range tmp[:n] {
			if b == '\r' || b == '\n' || b == ' ' || b == '\t' {
				continue
			}
			if kept < len(p) {
				p[kept] = b
				kept++
			}
		}
		if kept > 0 || err != nil || n == 0 {
			return kept, err
		}
	}
}

func decodeHeader(value string) string {
	dec := new(mime.WordDecoder)
	text, err := dec.DecodeHeader(value)
	if err != nil || text == "" {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(text)
}
