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
	"io"
)

// AptMessageWriter supports writing Apt messages.
type AptMessageWriter struct {
	writer io.Writer
}

// NewAptMessageWriter returns an AptMessageWriter.
func NewAptMessageWriter(w io.Writer) *AptMessageWriter {
	return &AptMessageWriter{writer: w}
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

// URIStart writes a 200 URI Start message.
func (w *AptMessageWriter) URIStart(uri, size, lastModified string) error {
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
