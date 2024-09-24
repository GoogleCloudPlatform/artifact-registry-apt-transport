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
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
)

// NewAptMethod returns an AptMethod.
func NewAptMethod(input *bufio.Reader, output io.Writer) *Method {
	return &Method{
		config: &aptMethodConfig{},
		writer: NewAptMessageWriter(output),
		reader: NewAptMessageReader(input),
		dl:     downloaderImpl{},
	}
}

// httpClient exists to enable mocking of http.Client.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// downloader exists to enable mocking of AptMethod.download.
type downloader interface {
	download(io.ReadCloser, string) (string, error)
}

type downloaderImpl struct{}

// Method represents the method handler.
type Method struct {
	reader *MessageReader
	writer *MessageWriter
	config *aptMethodConfig
	client httpClient
	dl     downloader
}

type aptMethodConfig struct {
	serviceAccountJSON, serviceAccountEmail string
	debug                                   bool
}

// Run runs the method.
func (m *Method) Run(ctx context.Context) error {
	m.writer.SendCapabilities()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		msg, err := m.reader.ReadMessage(ctx)
		if errors.Is(err, errEmptyMessage) {
			continue
		} else if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		switch msg.code {
		case 600:
			m.handleAcquire(ctx, msg)
		case 601:
			m.handleConfigure(msg)
		default:
			// TODO(hopkiw): now write a test for this.
			m.writer.Fail(fmt.Sprintf("Unsupported message code %d received from apt", msg.code))
		}
	}
}

func (m *Method) initClient(ctx context.Context) error {
	if m.client != nil {
		return nil
	}

	var ts oauth2.TokenSource
	switch {
	case m.config.serviceAccountJSON != "":
		json, err := os.ReadFile(m.config.serviceAccountJSON)
		if err != nil {
			return fmt.Errorf("failed to read service account JSON file: %v", err)
		}
		creds, err := google.CredentialsFromJSON(ctx, json, cloudPlatformScope)
		if err != nil {
			return fmt.Errorf("failed to obtain creds from service account JSON: %v", err)
		}
		ts = creds.TokenSource
	case m.config.serviceAccountEmail != "":
		ts = google.ComputeTokenSource(m.config.serviceAccountEmail)
	default:
		creds, err := google.FindDefaultCredentials(ctx, cloudPlatformScope)
		if err != nil {
			return fmt.Errorf("failed to obtain default creds: %v", err)
		}
		ts = creds.TokenSource
	}
	if ts == nil {
		return errors.New("failed to obtain creds")
	}
	m.client = oauth2.NewClient(ctx, ts)
	return nil
}

// download performs the actual downloading to target file and returns
// an MD5 hash of the downloaded file.
func (r downloaderImpl) download(body io.ReadCloser, filename string) (string, error) {
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}
	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = file.Write(data)
	return fmt.Sprintf("%x", md5.Sum(data)), err
}

func (m *Method) handleAcquire(ctx context.Context, msg *Message) error {
	uri := msg.Get("URI")
	if uri == "" {
		err := errors.New("no URI provided in Acquire message")
		m.writer.Fail(err.Error())
		return err
	}
	filename := msg.Get("Filename")
	if filename == "" {
		err := errors.New("no filename provided in Acquire message")
		m.writer.FailURI(uri, err.Error())
		return err
	}
	ifModifiedSince := msg.Get("Last-Modified")

	if err := m.initClient(ctx); err != nil {
		m.writer.FailURI(uri, err.Error())
		return err
	}

	realuri := strings.Replace(uri, "ar+https", "https", 1)
	req, err := http.NewRequest("GET", realuri, nil)
	if err != nil {
		return err
	}
	if ifModifiedSince != "" {
		// TODO(hopkiw): validate this string is in RFC1123Z format.
		req.Header.Add("If-Modified-Since", ifModifiedSince)
	}

	if m.config.debug {
		if reqDump, dumpErr := httputil.DumpRequest(req, true); dumpErr == nil {
			m.writer.Log(string(reqDump))
		}
	}

	resp, err := m.client.Do(req)

	if m.config.debug && resp != nil {
		if respDump, dumpErr := httputil.DumpResponse(resp, false); dumpErr == nil {
			m.writer.Log(string(respDump))
		}
	}

	if err != nil {
		m.writer.FailURI(uri, err.Error())
		return err
	}

	size := resp.Header.Get("Content-Length")
	lastModified := resp.Header.Get("Last-Modified")
	switch resp.StatusCode {
	case 200:
		// It's weird to send URI Start after we've already contacted
		// the server, but we need to know the size.
		m.writer.URIStart(uri, size, lastModified)
		md5Hash, err := m.dl.download(resp.Body, filename)
		if err != nil {
			m.writer.FailURI(uri, err.Error())
			return err
		}
		m.writer.URIDone(uri, size, lastModified, md5Hash, filename, false)
	case 304:
		// Unchanged since Last-Modified. Respond with "IMS-Hit: true" to
		// indicate the existing file is valid.
		m.writer.URIDone(uri, size, lastModified, "", filename, true)
	default:
		// All other codes including 404, 403, etc.
		err := fmt.Errorf("error downloading: code %v", resp.StatusCode)
		m.writer.FailURI(uri, err.Error())
		return err
	}

	return nil
}

// Ported from apt's `StringToBool` function
// https://salsa.debian.org/apt-team/apt/-/blob/a0a76c2e20c1ddefd76a4a539a9350b96d66006e/apt-pkg/contrib/strutl.cc#L824
func stringToBool(s string) bool {
	if i, err := strconv.Atoi(s); err == nil {
		if i == 1 {
			return true
		}
		return false
	}

	sl := strings.ToLower(s)
	trueStrs := []string{"yes", "true", "with", "on", "enable"}
	for _, trueStr := range trueStrs {
		if sl == trueStr {
			return true
		}
	}

	return false
}

func (m *Method) handleConfigure(msg *Message) {
	configs, ok := msg.fields["Config-Item"]
	if !ok {
		// Nothing to set.
		return
	}
	for _, configItem := range configs {
		parts := strings.SplitN(configItem, "=", 2)
		if len(parts) != 2 {
			m.writer.Log(fmt.Sprintf("malformed config item: %v", configItem))
			return
		}
		switch parts[0] {
		case "Acquire::gar::Service-Account-JSON":
			m.config.serviceAccountJSON = strings.TrimSpace(parts[1])
		case "Acquire::gar::Service-Account-Email":
			m.config.serviceAccountEmail = strings.TrimSpace(parts[1])
		case "Debug::Acquire::gar":
			m.config.debug = stringToBool(strings.TrimSpace(parts[1]))
		}
	}
	// Enforce the precedence of these two options.
	if m.config.serviceAccountJSON != "" {
		m.config.serviceAccountEmail = ""
	}
}
