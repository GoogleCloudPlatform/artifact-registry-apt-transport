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
	"io"
	"net/http"
	"testing"
)

func TestHandleConfigure(t *testing.T) {
	var tests = []struct {
		configItems []string
		expected    aptMethodConfig
	}{
		{
			[]string{
				"Acquire::gar::Service-Account-JSON=/path/to/creds.json",
				"Acquire::gar::Service-Account-Email=email-address@domain",
			},
			aptMethodConfig{serviceAccountJSON: "/path/to/creds.json"},
		},
		{
			[]string{
				"Acquire::gar::Service-Account-Email=email-address@domain",
			},
			aptMethodConfig{serviceAccountEmail: "email-address@domain"},
		},
		{
			[]string{
				"some::other::config=value",
			},
			aptMethodConfig{},
		},
	}

	for _, tt := range tests {
		method := &AptMethod{config: &aptMethodConfig{}}
		msg := &AptMessage{
			code:        601,
			description: "Configuration",
			fields:      map[string][]string{"Config-Item": tt.configItems},
		}

		method.handleConfigure(msg)
		if method.config.serviceAccountJSON != tt.expected.serviceAccountJSON {
			t.Errorf("path config items don't match, got %q expected %q", method.config.serviceAccountJSON, tt.expected.serviceAccountJSON)
		}
		if method.config.serviceAccountEmail != tt.expected.serviceAccountEmail {
			t.Errorf("email config items don't match, got %q expected %q", method.config.serviceAccountEmail, tt.expected.serviceAccountEmail)
		}

	}

}

type fakeHTTPClient struct {
	code   int
	header map[string][]string
}

func (m fakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.code == 0 {
		m.code = 200
	}
	if m.header == nil {
		m.header = map[string][]string{"Content-Length": []string{"200"}, "Last-Modified": []string{"whenever"}}
	}
	return &http.Response{StatusCode: m.code, Header: m.header}, nil
}

type fakeDownloader struct{}

func (d fakeDownloader) download(_ io.ReadCloser, _ string) (string, error) {
	return "ABCDEFGHI", nil
}

func TestAptMethodRun(t *testing.T) {

	stdinreader, stdinwriter := io.Pipe()
	stdoutreader, stdoutwriter := io.Pipe()
	workMethod := NewAptMethod(bufio.NewReader(stdinreader), stdoutwriter)
	workMethod.client = fakeHTTPClient{}
	workMethod.dl = fakeDownloader{}

	ctx := context.Background()
	ctx2, cancel := context.WithCancel(ctx)
	go workMethod.Run(ctx2)

	reader := AptMessageReader{reader: bufio.NewReader(stdoutreader)}
	msg, err := reader.ReadMessage(ctx)
	if err != nil {
		t.Errorf("failed, %v", err)
	}
	if msg.code != 100 || msg.description != "Capabilities" {
		t.Errorf("failed, didn't receive capabilities message")
	}

	writer := AptMessageWriter{writer: stdinwriter}
	writer.WriteMessage(AptMessage{
		code:        601,
		description: "Configuration",
		fields:      map[string][]string{"Config-Item": []string{"Acquire::gar::Service-Account-Email=email@domain"}},
	})

	writer.WriteMessage(AptMessage{
		code:        600,
		description: "URI Acquire",
		fields:      map[string][]string{"URI": []string{"http://fake.uri"}, "Filename": []string{"/path/to/file"}},
	})

	msg, err = reader.ReadMessage(ctx)
	if err != nil {
		t.Errorf("failed, %v", err)
	}
	if msg.code != 200 || msg.description != "URI Start" ||
		msg.Get("URI") != "http://fake.uri" || msg.Get("Size") != "200" {
		t.Errorf("failed, didn't receive uri start message. msg is %q", msg)
	}

	msg, err = reader.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("failed, %v", err)
	}
	if msg.code != 201 || msg.description != "URI Done" ||
		msg.Get("URI") != "http://fake.uri" || msg.Get("Filename") != "/path/to/file" {
		t.Errorf("failed, didn't receive uri start message. msg is %q", msg)
	}
	cancel()

	// This was set after we sent the 601, but for guaranteed timing in the
	// test we don't check until after we've read a reply message.
	if workMethod.config.serviceAccountEmail != "email@domain" {
		t.Errorf("failed, didn't set method configuration. got %v, expected %q", workMethod.config.serviceAccountEmail, "email@domain")
	}

	for _, p := range []io.Closer{stdinreader, stdinwriter, stdoutreader, stdoutwriter} {
		if err := p.Close(); err != nil {
			t.Errorf("Error from %v: %v", p, err)
		}
	}
}

func TestAptMethodRun404(t *testing.T) {

	stdinreader, stdinwriter := io.Pipe()
	stdoutreader, stdoutwriter := io.Pipe()
	workMethod := NewAptMethod(bufio.NewReader(stdinreader), stdoutwriter)
	workMethod.client = fakeHTTPClient{code: 404}
	workMethod.dl = fakeDownloader{}

	ctx := context.Background()
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	go workMethod.Run(ctx2)

	reader := AptMessageReader{reader: bufio.NewReader(stdoutreader)}
	msg, err := reader.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("failed, %v", err)
	}
	if msg.code != 100 || msg.description != "Capabilities" {
		t.Errorf("failed, didn't receive capabilities message")
	}

	writer := AptMessageWriter{writer: stdinwriter}
	writer.WriteMessage(AptMessage{
		code:        600,
		description: "URI Acquire",
		fields:      map[string][]string{"URI": []string{"http://fake.uri"}, "Filename": []string{"/path/to/file"}},
	})

	msg, err = reader.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("failed, %v", err)
	}
	if msg.code != 400 || msg.description != "URI Failure" ||
		msg.Get("URI") != "http://fake.uri" || msg.Get("Message") == "" {
		t.Errorf("failed, didn't receive uri failure message. msg is %q", msg)
	}
	cancel()

	for _, p := range []io.Closer{stdinreader, stdinwriter, stdoutreader, stdoutwriter} {
		if err := p.Close(); err != nil {
			t.Errorf("Error from %v: %v", p, err)
		}
	}
}

func TestAptMethodRun304(t *testing.T) {

	stdinreader, stdinwriter := io.Pipe()
	stdoutreader, stdoutwriter := io.Pipe()
	workMethod := NewAptMethod(bufio.NewReader(stdinreader), stdoutwriter)
	workMethod.client = fakeHTTPClient{code: 304}
	workMethod.dl = fakeDownloader{}

	ctx := context.Background()
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	go workMethod.Run(ctx2)

	reader := AptMessageReader{reader: bufio.NewReader(stdoutreader)}
	msg, err := reader.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("failed, %v", err)
	}
	if msg.code != 100 || msg.description != "Capabilities" {
		t.Errorf("failed, didn't receive capabilities message")
	}

	writer := AptMessageWriter{writer: stdinwriter}
	writer.WriteMessage(AptMessage{
		code:        600,
		description: "URI Acquire",
		fields:      map[string][]string{"URI": []string{"http://fake.uri"}, "Filename": []string{"/path/to/file"}},
	})

	msg, err = reader.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("failed, %v", err)
	}
	if msg.code != 201 || msg.description != "URI Done" ||
		msg.Get("URI") != "http://fake.uri" || msg.Get("IMS-Hit") != "true" {
		t.Errorf("failed, didn't receive uri done message. msg is %q", msg)
	}
	cancel()

	for _, p := range []io.Closer{stdinreader, stdinwriter, stdoutreader, stdoutwriter} {
		if err := p.Close(); err != nil {
			t.Errorf("Error from %v: %v", p, err)
		}
	}
}

func TestAptMethodRunFail(t *testing.T) {

	stdinreader, stdinwriter := io.Pipe()
	stdoutreader, stdoutwriter := io.Pipe()
	workMethod := NewAptMethod(bufio.NewReader(stdinreader), stdoutwriter)
	workMethod.client = fakeHTTPClient{code: 404}
	workMethod.dl = fakeDownloader{}

	ctx := context.Background()
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	go workMethod.Run(ctx2)

	reader := AptMessageReader{reader: bufio.NewReader(stdoutreader)}
	msg, err := reader.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("failed, %v", err)
	}
	if msg.code != 100 || msg.description != "Capabilities" {
		t.Errorf("failed, didn't receive capabilities message")
	}

	writer := AptMessageWriter{writer: stdinwriter}
	writer.WriteMessage(AptMessage{
		code:        700,
		description: "Bogus method",
	})

	msg, err = reader.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("failed, %v", err)
	}
	if msg.code != 401 || msg.description != "General Failure" || msg.Get("Message") == "" {
		t.Errorf("failed, didn't receive general failure message. msg is %q", msg)
	}
	cancel()

	for _, p := range []io.Closer{stdinreader, stdinwriter, stdoutreader, stdoutwriter} {
		if err := p.Close(); err != nil {
			t.Errorf("Error from %v: %v", p, err)
		}
	}
}
