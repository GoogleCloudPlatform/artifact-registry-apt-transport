//  Copyright 2021 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package apt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// AptMessage represents a single RFC822 Apt message.
type AptMessage struct {
	code        int
	description string
	fields      map[string][]string
}

// AptMessageReader supports reading Apt messages.
type AptMessageReader struct {
	reader  *bufio.Reader
	message *AptMessage
}

// AptMessageWriter supports writing Apt messages.
type AptMessageWriter struct {
	writer io.Writer
}

// Get returns the first AptMessage Field for `key`, or "".
func (m *AptMessage) Get(key string) string {
	if vals, ok := m.fields[key]; ok {
		if len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// NewAptMessageReader returns an AptMessageReader.
func NewAptMessageReader(r *bufio.Reader) *AptMessageReader {
	return &AptMessageReader{reader: r}
}

// NewAptMessageWriter returns an AptMessageWriter.
func NewAptMessageWriter(w io.Writer) *AptMessageWriter {
	return &AptMessageWriter{writer: w}
}

func (m *AptMessage) String() string {
	// Map iteration is unordered. For testing convenience, write alphabetical output.
	sortedKeys := make([]string, len(m.fields))
	i := 0
	for key := range m.fields {
		sortedKeys[i] = key
		i++
	}
	sort.Strings(sortedKeys)

	message := []string{fmt.Sprintf("%d %s", m.code, m.description)}
	for _, key := range sortedKeys {
		for _, val := range m.fields[key] {
			message = append(message, fmt.Sprintf("%s: %s", key, val))
		}
	}
	message = append(message, "")
	message = append(message, "") // End with a newline.
	return strings.Join(message, "\n")
}

// WriteMessage writes an AptMessage.
func (w *AptMessageWriter) WriteMessage(m AptMessage) error {
	return w.writeString(m.String())
}

// WriteString writes a raw string.
func (w *AptMessageWriter) writeString(s string) error {
	if _, err := w.writer.Write([]byte(s)); err != nil {
		return err
	}
	return nil
}

// SendCapabilities writes a 100 Capabilities message.
func (w *AptMessageWriter) SendCapabilities() error {
	return w.WriteMessage(new100Message())
}

// Log writes a 101 Log message.
func (w *AptMessageWriter) Log(msg string) error {
	return w.WriteMessage(new101Message(msg))
}

// TODO: validating doesn't make sense here if noone ever checks this error
// URIStart writes a 200 URI Start message.
func (w *AptMessageWriter) URIStart(uri, size, lastModified string) error {
	if uri == "" || size == "" {
		return errors.New("Must provide URI and Size")
	}
	return w.WriteMessage(new200Message(uri, size, lastModified))
}

// URIDone writes a 201 URI Done message.
func (w *AptMessageWriter) URIDone(uri, size, lastModified, md5Hash, filename string, ims bool) error {
	return w.WriteMessage(new201Message(uri, size, lastModified, md5Hash, filename, ims))
}

// FailURI writes a 400 URI Failure message.
func (w *AptMessageWriter) FailURI(uri, msg string) error {
	return w.WriteMessage(new400Message(uri, msg))
}

// Fail writes a 401 General Failure message.
func (w *AptMessageWriter) Fail(msg string) error {
	return w.WriteMessage(new401Message(msg))
}

// ReadMessage reads lines from `reader` until a complete message is received.
func (r *AptMessageReader) ReadMessage(ctx context.Context) (*AptMessage, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		line, err := r.reader.ReadString('\n')
		if err != nil {
			/*
				if err == io.EOF || err == io.ErrClosedPipe {
					// TODO: what to return in this case?
				}
			*/
			return nil, err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			if r.message == nil {
				return nil, errors.New("Empty message")
			}

			// Message is done, return and reset.
			msg := r.message
			r.message = nil
			return msg, nil
		}

		if r.message == nil {
			r.message = &AptMessage{}
			if err := r.parseHeader(line); err != nil {
				return nil, err
			}
		} else {
			if err := r.parseField(line); err != nil {
				return nil, err
			}
		}
	}
}

func (r *AptMessageReader) parseHeader(line string) error {
	if line == "" {
		return errors.New("Empty message header")
	}
	if r.message.code != 0 || r.message.description != "" {
		return errors.New("Double parsing header")
	}
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return errors.New("Malformed header")
	}
	code, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return errors.New("Malformed header")
	}

	r.message.code = code
	r.message.description = strings.TrimSpace(parts[1])
	return nil
}

func (r *AptMessageReader) parseField(line string) error {
	if line == "" {
		return errors.New("Empty message field")
	}
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return errors.New("Malformed field")
	}
	if r.message.fields == nil {
		r.message.fields = make(map[string][]string)
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if key == "" || value == "" {
		return errors.New("Malformed field")
	}

	fieldlist := r.message.fields[key]
	fieldlist = append(fieldlist, value)
	r.message.fields[key] = fieldlist
	return nil
}

func new100Message() AptMessage {
	fields := make(map[string][]string)
	fields["Send-Config"] = []string{"true"}
	fields["Version"] = []string{"1.0"}
	return AptMessage{code: 100, description: "Capabilities", fields: fields}
}

func new101Message(msg string) AptMessage {
	fields := make(map[string][]string)
	fields["Message"] = []string{msg}
	return AptMessage{code: 101, description: "Log", fields: fields}
}

func new200Message(uri, size, lastModified string) AptMessage {
	fields := make(map[string][]string)
	fields["URI"] = []string{uri}
	fields["Size"] = []string{size}
	if lastModified != "" {
		fields["Last-Modified"] = []string{lastModified}
	}
	fields["Resume-Point"] = []string{"0"}
	return AptMessage{code: 200, description: "URI Start", fields: fields}
}

func new201Message(uri, size, lastModified, md5Hash, filename string, ims bool) AptMessage {
	fields := make(map[string][]string)
	fields["URI"] = []string{uri}
	fields["Last-Modified"] = []string{lastModified}
	fields["Filename"] = []string{filename}
	if ims {
		fields["IMS-Hit"] = []string{"true"}
	} else {
		fields["Size"] = []string{size}
		fields["MD5-Hash"] = []string{md5Hash}
	}
	return AptMessage{code: 201, description: "URI Done", fields: fields}
}

func new400Message(uri, msg string) AptMessage {
	fields := make(map[string][]string)
	fields["URI"] = []string{uri}
	fields["Message"] = []string{msg}
	return AptMessage{code: 400, description: "URI Failure", fields: fields}
}

func new401Message(msg string) AptMessage {
	fields := make(map[string][]string)
	fields["Message"] = []string{msg}
	return AptMessage{code: 401, description: "General Failure", fields: fields}
}
