package rewrites

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type headerOpType int

const (
	headerOpDel headerOpType = iota
	headerOpSet
	headerOpAdd
)

type headerOp struct {
	typ   headerOpType
	name  string
	value string
}

type bodyOpType int

const (
	bodyOpReplace bodyOpType = iota
	bodyOpRegex
)

type bodyOp struct {
	typ         bodyOpType
	from        []byte
	to          []byte
	re          regexLike
	replacement []byte
}

type regexLike interface {
	Match([]byte) bool
	ReplaceAll([]byte, []byte) []byte
}

// Plan is the ordered set of changes to apply to a response.
type Plan struct {
	appliedRules []string
	headerOps    []headerOp
	bodyOps      []bodyOp
}

func (p *Plan) AppliedRules() []string {
	return append([]string{}, p.appliedRules...)
}

func (p *Plan) HasChanges() bool {
	return len(p.headerOps) > 0 || len(p.bodyOps) > 0
}

func (p *Plan) NeedsBody() bool {
	return len(p.bodyOps) > 0
}

func (p *Plan) ApplyHeaders(h http.Header) {
	for _, op := range p.headerOps {
		switch op.typ {
		case headerOpDel:
			h.Del(op.name)
		case headerOpSet:
			h.Set(op.name, op.value)
		case headerOpAdd:
			h.Add(op.name, op.value)
		}
	}
}

var ErrUnsupportedContentEncoding = errors.New("unsupported content-encoding")

const maxDecodedBodyBytes = 20 << 20 // 20 MiB

// RewriteBody applies body operations to rawBody (as received from upstream) and updates headers
// if the output differs. If no body changes occur, headers are left untouched.
func (p *Plan) RewriteBody(h http.Header, rawBody []byte) ([]byte, bool, error) {
	if len(p.bodyOps) == 0 {
		return rawBody, false, nil
	}

	encoding, err := parseSingleContentEncoding(h.Get("Content-Encoding"))
	if err != nil {
		return rawBody, false, err
	}

	decoded, err := decodeBody(encoding, rawBody)
	if err != nil {
		return rawBody, false, err
	}

	changed := false
	modified := decoded
	for _, op := range p.bodyOps {
		switch op.typ {
		case bodyOpReplace:
			if !bytes.Contains(modified, op.from) {
				continue
			}
			modified = bytes.ReplaceAll(modified, op.from, op.to)
			changed = true
		case bodyOpRegex:
			if op.re == nil || !op.re.Match(modified) {
				continue
			}
			modified = op.re.ReplaceAll(modified, op.replacement)
			changed = true
		}
	}

	if !changed {
		return rawBody, false, nil
	}

	encoded, err := encodeBody(encoding, modified)
	if err != nil {
		return rawBody, false, err
	}

	// Body changed: fix up framing headers and remove cache validators that are now wrong.
	h.Del("Transfer-Encoding")
	h.Set("Content-Length", strconv.Itoa(len(encoded)))
	h.Del("Etag")
	h.Del("Content-Md5")

	return encoded, true, nil
}

func parseSingleContentEncoding(v string) (string, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" || v == "identity" {
		return "", nil
	}
	if strings.Contains(v, ",") {
		return "", fmt.Errorf("%w: %q", ErrUnsupportedContentEncoding, v)
	}
	switch v {
	case "gzip", "deflate":
		return v, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedContentEncoding, v)
	}
}

func decodeBody(encoding string, raw []byte) ([]byte, error) {
	if encoding == "" || len(raw) == 0 {
		return raw, nil
	}

	var r io.ReadCloser
	switch encoding {
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		r = gr
	case "deflate":
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		r = zr
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedContentEncoding, encoding)
	}
	defer r.Close()

	decoded, err := io.ReadAll(io.LimitReader(r, maxDecodedBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(decoded) > maxDecodedBodyBytes {
		return nil, fmt.Errorf("decoded body exceeds %d bytes", maxDecodedBodyBytes)
	}
	return decoded, nil
}

func encodeBody(encoding string, decoded []byte) ([]byte, error) {
	if encoding == "" || len(decoded) == 0 {
		return decoded, nil
	}

	var buf bytes.Buffer
	var w io.WriteCloser
	switch encoding {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "deflate":
		w = zlib.NewWriter(&buf)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedContentEncoding, encoding)
	}

	if _, err := w.Write(decoded); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (r compiledRule) hasBodyOps() bool {
	return len(r.bodyOps) > 0
}

func (r compiledRule) requestMatches(req *http.Request, targetHost string) bool {
	return r.matchRequest(req, targetHost)
}

func (r compiledRule) matches(req *http.Request, targetHost string, statusCode int, respHeader http.Header) bool {
	if !r.matchRequest(req, targetHost) {
		return false
	}

	if len(r.match.statuses) > 0 {
		if _, ok := r.match.statuses[statusCode]; !ok {
			return false
		}
	}

	if r.match.contentTypeContains != "" || r.match.contentTypeRegex != nil {
		ct := strings.ToLower(respHeader.Get("Content-Type"))
		if r.match.contentTypeContains != "" && !strings.Contains(ct, r.match.contentTypeContains) {
			return false
		}
		if r.match.contentTypeRegex != nil && !r.match.contentTypeRegex.MatchString(ct) {
			return false
		}
	}

	if len(r.match.respHeaderContains) > 0 {
		for k, want := range r.match.respHeaderContains {
			if !headerContains(respHeader, k, want) {
				return false
			}
		}
	}

	return true
}

func (r compiledRule) matchRequest(req *http.Request, targetHost string) bool {
	host := strings.ToLower(strings.TrimSpace(targetHost))
	if r.match.host != "" && host != r.match.host {
		return false
	}
	if r.match.hostRegex != nil && !r.match.hostRegex.MatchString(host) {
		return false
	}

	uri := ""
	if req != nil && req.URL != nil {
		uri = req.URL.RequestURI()
	}
	if r.match.pathPrefix != "" && !strings.HasPrefix(uri, r.match.pathPrefix) {
		return false
	}
	if r.match.pathRegex != nil && !r.match.pathRegex.MatchString(uri) {
		return false
	}

	if len(r.match.methods) > 0 {
		method := ""
		if req != nil {
			method = strings.ToUpper(req.Method)
		}
		if _, ok := r.match.methods[method]; !ok {
			return false
		}
	}

	if len(r.match.reqHeaderContains) > 0 {
		var reqHeader http.Header
		if req != nil {
			reqHeader = req.Header
		}
		for k, want := range r.match.reqHeaderContains {
			if !headerContains(reqHeader, k, want) {
				return false
			}
		}
	}

	return true
}

func headerContains(h http.Header, key, want string) bool {
	if h == nil {
		return false
	}
	values := h.Values(key)
	for _, v := range values {
		if strings.Contains(v, want) {
			return true
		}
	}
	return false
}
