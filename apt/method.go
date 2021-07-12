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
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
)

// NewAptMethod returns an AptMethod.
func NewAptMethod(input *bufio.Reader, output io.Writer) *AptMethod {
	return &AptMethod{
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

// AptMethod represents the method handler.
type AptMethod struct {
	reader *AptMessageReader
	writer *AptMessageWriter
	config *aptMethodConfig
	client httpClient
	dl     downloader
}

type aptMethodConfig struct {
	serviceAccountJSON, serviceAccountEmail string
}

// Run runs the method.
func (m *AptMethod) Run(ctx context.Context) {
	m.writer.SendCapabilities()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		msg, err := m.reader.ReadMessage(ctx)
		if err != nil {
			continue
		}
		switch msg.code {
		case 600:
			m.handleAcquire(msg)
		case 601:
			m.handleConfigure(msg)
		default:
			// TODO: now write a test for this.
			m.writer.Fail(fmt.Sprintf("Unsupported message code %d received from apt", msg.code))
		}
	}
}

func (m *AptMethod) initClient() error {
	if m.client != nil {
		return nil
	}

	var ts oauth2.TokenSource
	ctx := context.Background()
	switch {
	case m.config.serviceAccountJSON != "":
		json, err := ioutil.ReadFile(m.config.serviceAccountJSON)
		if err != nil {
			return fmt.Errorf("Failed to obtain creds: %v", err)
		}
		creds, err := google.CredentialsFromJSON(ctx, json, cloudPlatformScope)
		if err != nil {
			return fmt.Errorf("Failed to obtain creds: %v", err)
		}
		ts = creds.TokenSource
	case m.config.serviceAccountEmail != "":
		ts = google.ComputeTokenSource(m.config.serviceAccountEmail)
	default:
		creds, err := google.FindDefaultCredentials(ctx)
		if err != nil {
			return fmt.Errorf("Failed to obtain creds: %v", err)
		}
		ts = creds.TokenSource
	}
	if ts == nil {
		return errors.New("Failed to obtain creds")
	}
	m.client = oauth2.NewClient(ctx, ts)
	return nil
}

// download performs the actual downloading to target file and returns
// an MD5 hash of the downloaded file.
func (r downloaderImpl) download(body io.ReadCloser, filename string) (string, error) {
	defer body.Close()
	data, err := ioutil.ReadAll(body)
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

func (m *AptMethod) handleAcquire(msg *AptMessage) error {
	uri := msg.Get("URI")
	if uri == "" {
		err := errors.New("No URI provided in Acquire message")
		m.writer.Fail(err.Error())
		return err
	}
	filename := msg.Get("Filename")
	if filename == "" {
		err := errors.New("No filename provided in Acquire message")
		m.writer.FailURI(uri, err.Error())
		return err
	}
	ifModifiedSince := msg.Get("Last-Modified")

	if err := m.initClient(); err != nil {
		m.writer.FailURI(uri, err.Error())
		return err
	}

	realuri := strings.Replace(uri, "ar+https", "https", 1)
	req, err := http.NewRequest("GET", realuri, nil)
	if err != nil {
		return err
	}
	if ifModifiedSince != "" {
		// TODO: validate this string is in RFC1123Z format.
		req.Header.Add("If-Modified-Since", ifModifiedSince)
	}
	resp, err := m.client.Do(req)
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
		err := fmt.Errorf("Error downloading: code %v", resp.StatusCode)
		m.writer.FailURI(uri, err.Error())
		return err
	}

	return nil
}

func (m *AptMethod) handleConfigure(msg *AptMessage) {
	configs, ok := msg.fields["Config-Item"]
	if !ok {
		// Nothing to set.
		return
	}
	for _, configItem := range configs {
		if strings.Contains(configItem, "Acquire::gar::Service-Account-JSON") {
			parts := strings.SplitN(configItem, "=", 2)
			if len(parts) != 2 {
				// TODO: log this?
				return
			}
			m.config.serviceAccountJSON = strings.TrimSpace(parts[1])
		}
		if strings.Contains(configItem, "Acquire::gar::Service-Account-Email") {
			parts := strings.SplitN(configItem, "=", 2)
			if len(parts) != 2 {
				// TODO: log this?
				return
			}
			m.config.serviceAccountEmail = strings.TrimSpace(parts[1])
		}
	}
	// Enforce the precedence of these two options.
	if m.config.serviceAccountJSON != "" {
		m.config.serviceAccountEmail = ""
	}
}
