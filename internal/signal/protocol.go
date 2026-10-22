package signal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// This development profile deliberately does not advertise the unfinished
// production protocol (tickets, TURN authorization and overload challenges).
const Subprotocol = "xfs-signal.dev.v1"
const MaxMessage = 64 * 1024

type request struct {
	Type    string  `json:"t"`
	ID      string  `json:"id,omitempty"`
	Version *uint   `json:"v,omitempty"`
	Client  string  `json:"client,omitempty"`
	Code    string  `json:"code,omitempty"`
	Room    string  `json:"room,omitempty"`
	Kind    string  `json:"kind,omitempty"`
	Payload *string `json:"payload,omitempty"`
	Reason  *uint   `json:"reason,omitempty"`
	PK      string  `json:"pk,omitempty"`
	Nonce   string  `json:"nonce,omitempty"`
	Sig     string  `json:"sig,omitempty"`
	PKHash  string  `json:"pkHash,omitempty"`
	Ticket  string  `json:"ticket,omitempty"`
	Claim   string  `json:"claim,omitempty"`
	TS      *uint64 `json:"ts,omitempty"`
	SDP     *bool   `json:"sdpNeeded,omitempty"`
}

type message map[string]any

func decode(data []byte) (request, error) {
	var r request
	if !utf8.Valid(data) {
		return r, errors.New("invalid utf8")
	}
	// Reject duplicate keys, including escaped spellings, before decoding.
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return r, errors.New("object required")
	}
	seen := map[string]bool{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return r, err
		}
		key, ok := t.(string)
		if !ok || seen[key] {
			return r, errors.New("duplicate key")
		}
		seen[key] = true
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil {
			return r, err
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return r, errors.New("null field")
		}
	}
	if _, err = d.Token(); err != nil {
		return r, err
	}
	if _, err = d.Token(); err != io.EOF {
		return r, errors.New("trailing data")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&r); err != nil {
		return r, err
	}
	if r.Type == "" {
		return r, errors.New("missing type")
	}
	if seen["id"] {
		id, err := base64.RawURLEncoding.DecodeString(r.ID)
		if err != nil || len(id) != 8 || base64.RawURLEncoding.EncodeToString(id) != r.ID {
			return r, errors.New("invalid id")
		}
	}
	allowed := map[string]string{"hello": "v client", "create_room": "", "join_room": "code", "signal": "room kind payload", "ready": "room pkHash", "resume": "ticket pk ts sig sdpNeeded", "claim_room": "claim", "bye": "room reason", "ping": "", "turn_credentials": "pk nonce sig"}
	fields, ok := allowed[r.Type]
	if !ok {
		return r, errors.New("unsupported message")
	}
	for key := range seen {
		if key != "t" && key != "id" && !bytes.Contains([]byte(" "+fields+" "), []byte(" "+key+" ")) {
			return r, errors.New("unexpected field")
		}
	}
	switch r.Type {
	case "hello":
		if r.Version == nil || len(r.Client) > 128 {
			return r, errors.New("invalid hello")
		}
	case "resume":
		if r.Ticket == "" || len(r.Ticket) > 128 || r.TS == nil || r.SDP == nil {
			return r, errors.New("missing resume fields")
		}
		for _, f := range []struct {
			v string
			n int
		}{{r.PK, 32}, {r.Sig, 64}} {
			b, err := base64.RawURLEncoding.DecodeString(f.v)
			if err != nil || len(b) != f.n {
				return r, errors.New("invalid resume field")
			}
		}
	case "turn_credentials":
		for _, f := range []struct {
			v string
			n int
		}{{r.PK, 32}, {r.Nonce, 32}, {r.Sig, 64}} {
			b, err := base64.RawURLEncoding.DecodeString(f.v)
			if err != nil || len(b) != f.n {
				return r, errors.New("invalid turn_credentials field")
			}
		}
	case "claim_room":
		if b, err := base64.RawURLEncoding.DecodeString(r.Claim); err != nil || len(b) != 16 {
			return r, errors.New("invalid claim")
		}
	case "join_room":
		if !seen["code"] {
			return r, errors.New("missing code")
		}
	case "signal":
		if r.Room == "" || r.Payload == nil {
			return r, errors.New("missing signal fields")
		}
		switch r.Kind {
		case "offer", "answer", "candidate", "candidate_end":
		default:
			return r, errors.New("invalid signal kind")
		}
	case "ready", "bye":
		if r.Room == "" {
			return r, errors.New("missing room")
		}
		if r.Type == "ready" {
			// 04 v1.5: each side names the identity its renewal ticket binds.
			if b, err := base64.RawURLEncoding.DecodeString(r.PKHash); err != nil || len(b) != 16 {
				return r, errors.New("invalid pkHash")
			}
		}
		if r.Type == "bye" && r.Reason == nil {
			return r, errors.New("missing reason")
		}
	}
	return r, nil
}

func failure(code int, retry int) message {
	m := message{"t": "error", "code": code, "message": "request rejected"}
	if retry > 0 {
		m["retryAfter"] = retry
	}
	return m
}
