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
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/oauth2"
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
		{
			[]string{
				"Debug::Acquire::gar=1",
			},
			aptMethodConfig{debug: true},
		},
		{
			[]string{
				"Debug::Acquire::gar=enable",
			},
			aptMethodConfig{debug: true},
		},
		{
			[]string{
				"Debug::Acquire::gar=10",
			},
			aptMethodConfig{debug: false},
		},
		{
			[]string{
				"Debug::Acquire::gar=0",
			},
			aptMethodConfig{debug: false},
		},
		{
			[]string{
				"Debug::Acquire::gar=-1",
			},
			aptMethodConfig{debug: false},
		},
	}

	for _, tt := range tests {
		method := &Method{config: &aptMethodConfig{}}
		msg := &Message{
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
		m.header = map[string][]string{"Content-Length": {"200"}, "Last-Modified": {"whenever"}}
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

	reader := MessageReader{reader: bufio.NewReader(stdoutreader)}
	msg, err := reader.ReadMessage(ctx)
	if err != nil {
		t.Errorf("failed, %v", err)
	}
	if msg.code != 100 || msg.description != "Capabilities" {
		t.Errorf("failed, didn't receive capabilities message")
	}

	writer := MessageWriter{writer: stdinwriter}
	writer.WriteMessage(Message{
		code:        601,
		description: "Configuration",
		fields:      map[string][]string{"Config-Item": {"Acquire::gar::Service-Account-Email=email@domain"}},
	})

	writer.WriteMessage(Message{
		code:        600,
		description: "URI Acquire",
		fields:      map[string][]string{"URI": {"http://fake.uri"}, "Filename": {"/path/to/file"}},
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

	reader := MessageReader{reader: bufio.NewReader(stdoutreader)}
	msg, err := reader.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("failed, %v", err)
	}
	if msg.code != 100 || msg.description != "Capabilities" {
		t.Errorf("failed, didn't receive capabilities message")
	}

	writer := MessageWriter{writer: stdinwriter}
	writer.WriteMessage(Message{
		code:        600,
		description: "URI Acquire",
		fields:      map[string][]string{"URI": {"http://fake.uri"}, "Filename": {"/path/to/file"}},
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

	reader := MessageReader{reader: bufio.NewReader(stdoutreader)}
	msg, err := reader.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("failed, %v", err)
	}
	if msg.code != 100 || msg.description != "Capabilities" {
		t.Errorf("failed, didn't receive capabilities message")
	}

	writer := MessageWriter{writer: stdinwriter}
	writer.WriteMessage(Message{
		code:        600,
		description: "URI Acquire",
		fields:      map[string][]string{"URI": {"http://fake.uri"}, "Filename": {"/path/to/file"}},
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
	errChan := make(chan error)
	go func() {
		errChan <- workMethod.Run(ctx2)
	}()

	reader := MessageReader{reader: bufio.NewReader(stdoutreader)}
	msg, err := reader.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("failed, %v", err)
	}
	if msg.code != 100 || msg.description != "Capabilities" {
		t.Errorf("failed, didn't receive capabilities message")
	}

	writer := MessageWriter{writer: stdinwriter}
	writer.WriteMessage(Message{
		code:        700,
		description: "Malformed message",
		fields:      map[string][]string{"": {"foo"}},
	})

	// If we receive a malformed message from `apt`, we immediately bail
	// without sending an error response. Unlike the other tests, there is no
	// protocol message to read here, but we can assert on the return value of
	// `Run`.
	runErr := <-errChan
	if runErr == nil {
		t.Fatalf("failed, expected non-nil runErr (empty key)")
	}
	if !strings.Contains(runErr.Error(), "malformed") {
		t.Fatalf("failed, expected runErr to contain 'malformed'")
	}

	for _, p := range []io.Closer{stdinreader, stdinwriter, stdoutreader, stdoutwriter} {
		if err := p.Close(); err != nil {
			t.Errorf("Error from %v: %v", p, err)
		}
	}
}

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (t *trackingReadCloser) Close() error {
	t.closed = true
	return nil
}

type failingReader struct {
	err error
}

func (f failingReader) Read([]byte) (int, error) {
	return 0, f.err
}

func TestDownloaderImplDownload(t *testing.T) {
	dl := downloaderImpl{}

	t.Run("streams multi-chunk payload to disk and returns MD5", func(t *testing.T) {
		payload := bytes.Repeat([]byte("artifact-registry-apt-stream-chunk-"), 4096) // ~140 KiB (> 32 KiB io.Copy buffer)
		wantHash := fmt.Sprintf("%x", md5.Sum(payload))
		body := &trackingReadCloser{Reader: bytes.NewReader(payload)}
		dest := filepath.Join(t.TempDir(), "pkg.deb")

		gotHash, err := dl.download(body, dest)
		if err != nil {
			t.Fatalf("download failed: %v", err)
		}
		if !body.closed {
			t.Error("expected response body to be closed")
		}
		if gotHash != wantHash {
			t.Errorf("got MD5 %q, want %q", gotHash, wantHash)
		}
		gotBytes, err := os.ReadFile(dest)
		if err != nil {
			t.Fatalf("os.ReadFile(%q) failed: %v", dest, err)
		}
		if !bytes.Equal(gotBytes, payload) {
			t.Errorf("downloaded file size = %d, want %d (contents mismatch)", len(gotBytes), len(payload))
		}
	})

	t.Run("returns error and closes body on stream read failure", func(t *testing.T) {
		readErr := errors.New("simulated network failure")
		body := &trackingReadCloser{
			Reader: io.MultiReader(strings.NewReader("partial-data"), failingReader{err: readErr}),
		}
		dest := filepath.Join(t.TempDir(), "partial.deb")

		_, err := dl.download(body, dest)
		if !errors.Is(err, readErr) {
			t.Fatalf("download error = %v, want %v", err, readErr)
		}
		if !body.closed {
			t.Error("expected response body to be closed on read error")
		}
	})

	t.Run("returns error and closes body on invalid destination path", func(t *testing.T) {
		body := &trackingReadCloser{Reader: strings.NewReader("data")}
		dest := filepath.Join(t.TempDir(), "nonexistent-dir", "pkg.deb")

		_, err := dl.download(body, dest)
		if err == nil {
			t.Fatal("download succeeded on nonexistent parent directory, want error")
		}
		if !body.closed {
			t.Error("expected response body to be closed when os.Create fails")
		}
	})
}

type bodyTrackingHTTPClient struct {
	code int
	body *trackingReadCloser
}

func (c bodyTrackingHTTPClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: c.code,
		Header:     http.Header{"Last-Modified": {"whenever"}},
		Body:       c.body,
	}, nil
}

func TestHandleAcquireClosesBodyOnNon200(t *testing.T) {
	for _, statusCode := range []int{http.StatusNotModified, http.StatusNotFound} {
		t.Run(fmt.Sprintf("status_%d", statusCode), func(t *testing.T) {
			body := &trackingReadCloser{Reader: strings.NewReader("response body")}
			var out bytes.Buffer
			m := &Method{
				config: &aptMethodConfig{},
				writer: NewAptMessageWriter(&out),
				client: bodyTrackingHTTPClient{code: statusCode, body: body},
				dl:     fakeDownloader{},
			}

			_ = m.handleAcquire(context.Background(), &Message{
				code:        600,
				description: "URI Acquire",
				fields: map[string][]string{
					"URI":      {"ar+https://us-apt.pkg.dev/projects/p/pkg.deb"},
					"Filename": {"/path/to/file"},
				},
			})

			if !body.closed {
				t.Errorf("expected resp.Body to be closed for status %d", statusCode)
			}
		})
	}
}

func TestCheckRedirect(t *testing.T) {
	originReq, err := http.NewRequest("GET", "https://us-apt.pkg.dev/projects/my-proj/dists/main/InRelease", nil)
	if err != nil {
		t.Fatalf("http.NewRequest failed: %v", err)
	}

	tests := []struct {
		name      string
		targetURL string
		hops      int
		wantErr   bool
	}{
		{
			name:      "same host HTTPS redirect allowed",
			targetURL: "https://us-apt.pkg.dev/projects/my-proj/pool/pkg.deb",
			hops:      1,
			wantErr:   false,
		},
		{
			name:      "case-insensitive same host HTTPS redirect allowed",
			targetURL: "https://US-APT.PKG.DEV/projects/my-proj/pool/pkg.deb",
			hops:      1,
			wantErr:   false,
		},
		{
			name:      "redirect to HTTP scheme blocked",
			targetURL: "http://us-apt.pkg.dev/projects/my-proj/pool/pkg.deb",
			hops:      1,
			wantErr:   true,
		},
		{
			name:      "redirect to different host blocked",
			targetURL: "https://attacker.example.com/pkg.deb",
			hops:      1,
			wantErr:   true,
		},
		{
			name:      "redirect to different port blocked",
			targetURL: "https://us-apt.pkg.dev:8443/projects/my-proj/pool/pkg.deb",
			hops:      1,
			wantErr:   true,
		},
		{
			name:      "redirect after 10 hops blocked",
			targetURL: "https://us-apt.pkg.dev/projects/my-proj/pool/pkg.deb",
			hops:      10,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tc.targetURL, nil)
			if err != nil {
				t.Fatalf("http.NewRequest(%q) failed: %v", tc.targetURL, err)
			}
			via := make([]*http.Request, tc.hops)
			for i := range via {
				via[i] = originReq
			}
			err = checkRedirect(req, via)
			if (err != nil) != tc.wantErr {
				t.Errorf("checkRedirect(%q, %d hops) error = %v, wantErr %v", tc.targetURL, tc.hops, err, tc.wantErr)
			}
		})
	}
}

func TestHandleAcquireRedirects(t *testing.T) {
	const secretToken = "secret-token-123"

	t.Run("blocks cross-host redirect and does not leak token", func(t *testing.T) {
		attackerCalled := false
		var leakedAuthHeader string
		attackerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attackerCalled = true
			leakedAuthHeader = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}))
		defer attackerServer.Close()

		registryServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, attackerServer.URL+"/pkg.deb", http.StatusFound)
		}))
		defer registryServer.Close()

		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, registryServer.Client())
		var out bytes.Buffer
		m := &Method{
			config: &aptMethodConfig{},
			writer: NewAptMessageWriter(&out),
			client: newOAuthClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: secretToken})),
			dl:     fakeDownloader{},
		}

		arURI := strings.Replace(registryServer.URL+"/pkg.deb", "https://", "ar+https://", 1)
		err := m.handleAcquire(ctx, &Message{
			code:        600,
			description: "URI Acquire",
			fields: map[string][]string{
				"URI":      {arURI},
				"Filename": {"/path/to/file"},
			},
		})
		if err == nil {
			t.Fatal("handleAcquire succeeded, want error on cross-host redirect")
		}
		if attackerCalled {
			t.Fatalf("attacker server was contacted (Authorization: %q), want redirect blocked before request", leakedAuthHeader)
		}
		if !strings.Contains(out.String(), "400 URI Failure") {
			t.Errorf("expected 400 URI Failure output, got %q", out.String())
		}
	})

	t.Run("allows same-host HTTPS redirect and preserves token", func(t *testing.T) {
		var finalAuthHeader string
		var registryURL string
		registryServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/redirect" {
				http.Redirect(w, r, registryURL+"/pkg.deb", http.StatusFound)
				return
			}
			finalAuthHeader = r.Header.Get("Authorization")
			w.Header().Set("Content-Length", "9")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ABCDEFGHI"))
		}))
		defer registryServer.Close()
		registryURL = registryServer.URL

		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, registryServer.Client())
		var out bytes.Buffer
		m := &Method{
			config: &aptMethodConfig{},
			writer: NewAptMessageWriter(&out),
			client: newOAuthClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: secretToken})),
			dl:     fakeDownloader{},
		}

		arURI := strings.Replace(registryServer.URL+"/redirect", "https://", "ar+https://", 1)
		err := m.handleAcquire(ctx, &Message{
			code:        600,
			description: "URI Acquire",
			fields: map[string][]string{
				"URI":      {arURI},
				"Filename": {"/path/to/file"},
			},
		})
		if err != nil {
			t.Fatalf("handleAcquire failed on same-host HTTPS redirect: %v", err)
		}
		if want := "Bearer " + secretToken; finalAuthHeader != want {
			t.Errorf("Authorization header on redirected request = %q, want %q", finalAuthHeader, want)
		}
		if !strings.Contains(out.String(), "201 URI Done") {
			t.Errorf("expected 201 URI Done output, got %q", out.String())
		}
	})
}
