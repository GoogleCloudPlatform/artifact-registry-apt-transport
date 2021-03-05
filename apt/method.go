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

func NewAptMethod(output io.Writer, input *bufio.Reader) *AptMethod {
	return &AptMethod{
		config: &AptMethodConfig{},
		writer: NewAptMessageWriter(output),
		reader: NewAptMessageReader(input),
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

type realDownloader struct{}

type AptMethod struct {
	config *AptMethodConfig
	writer *AptMessageWriter
	reader *AptMessageReader
	client httpClient
	dl     downloader
}

type AptMethodConfig struct {
	serviceAccountJSON, serviceAccountEmail string
}

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
			// TODO: log?
			continue
		}
		switch msg.code {
		case 600:
			m.handleAcquire(msg)
		case 601:
			m.handleConfigure(msg)
		default:
			m.writer.Fail("Unsupported API")
		}
	}
}

func (m *AptMethod) getClient() error {
	if m.client != nil {
		return nil
	}

	var ts oauth2.TokenSource
	ctx := context.Background()
	switch {
	case m.config.serviceAccountJSON != "":
		json, err := ioutil.ReadFile(m.config.serviceAccountJSON)
		if err == nil {
			creds, ierr := google.CredentialsFromJSON(ctx, json)
			if ierr == nil {
				ts = creds.TokenSource
			}
		}
	case m.config.serviceAccountEmail != "":
		ts = google.ComputeTokenSource(m.config.serviceAccountEmail)
	default:
		creds, err := google.FindDefaultCredentials(ctx)
		if err == nil {
			ts = creds.TokenSource
		}
	}
	if ts == nil {
		return errors.New("Failed to obtain token source")
	}
	m.client = oauth2.NewClient(ctx, ts)
	return nil
}

func (r realDownloader) download(body io.ReadCloser, filename string) (string, error) {
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

// TODO: testing. this validates the message (could be separated), optionally adds a header, makes a GET request, and sends appropriate 2xx messages to apt.
// it also returns an error that we don't care about..
func (m *AptMethod) handleAcquire(msg *AptMessage) error {
	// === VALIDATE MESSAGE ===
	uri := msg.Get("URI")
	if uri == "" {
		err := errors.New("No URI provided")
		m.writer.Fail(err.Error())
		return err
	}
	filename := msg.Get("Filename")
	if filename == "" {
		err := errors.New("No filename provided")
		m.writer.FailURI(uri, err.Error())
		return err
	}
	ifModifiedSince := msg.Get("Last-Modified")
	// === END VALIDATE MESSAGE ===

	// === GET CLIENT ===
	if err := m.getClient(); err != nil {
		m.writer.FailURI(uri, err.Error())
		return err
	}
	// === END GET CLIENT ===

	// === MAKE REQUEST ===
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
	// === END MAKE REQUEST ===

	// === HANDLE RESPONSE ===
	size := resp.Header.Get("Content-Length")
	lastModified := resp.Header.Get("Last-Modified")
	switch resp.StatusCode {
	case 200:
		// It's weird to send URI Start after we've already contacted
		// the server, but we need to know the size.
		m.writer.URIStart(uri, size, lastModified)
		if m.dl == nil {
			m.dl = realDownloader{}
		}
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
	// === END HANDLE RESPONSE ===

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
