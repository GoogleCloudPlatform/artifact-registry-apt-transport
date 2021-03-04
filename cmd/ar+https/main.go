package main

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
	"strconv"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	apt := NewAptMethod(os.Stdout, bufio.NewReader(os.Stdin))
	apt.Run()
}

func (m *AptMethod) Run() {
	m.writer.SendCapabilities()
	for {
		msg, err := m.reader.ReadMessage()
		if err != nil {
			m.writer.Log(fmt.Sprintf("Error reading APT message: %v", err))
			continue
		}
		switch msg.Code {
		case 600:
			m.handleAcquire(msg)
		case 601:
			m.handleConfigure(msg)
		default:
			m.writer.Fail("Unsupported API")
		}
	}
}

type AptMethod struct {
	config *AptMethodConfig
	writer *AptMessageWriter
	reader *AptMessageReader
	client *http.Client
}

func NewAptMethod(output io.Writer, input *bufio.Reader) *AptMethod {
	return &AptMethod{
		config: &AptMethodConfig{},
		writer: NewAptMessageWriter(output),
		reader: NewAptMessageReader(input),
	}
}

func (m *AptMethod) getClient() error {
	if m.client != nil {
		return nil
	}

	var ts oauth2.TokenSource
	ctx := context.Background()
	switch {
	case m.config.ServiceAccountJSON != "":
		json, err := ioutil.ReadFile(m.config.ServiceAccountJSON)
		if err == nil {
			creds, ierr := google.CredentialsFromJSON(ctx, json)
			if ierr == nil {
				ts = creds.TokenSource
			}
		}
		m.writer.Log("Using provided JSON credentials file for Google Artifact Registry")
	case m.config.ServiceAccountEmail != "":
		ts = google.ComputeTokenSource(m.config.ServiceAccountEmail)
		m.writer.Log("Using provided service account email for Google Artifact Registry")
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

func (m *AptMethod) download(body io.ReadCloser, filename string) (string, error) {
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
	if err := m.getClient(); err != nil {
		m.writer.FailURI(uri, err.Error())
		return err
	}
	realuri := strings.Replace(uri, "ar+https", "https", 1)
	req, err := http.NewRequest("GET", realuri, nil)
	if err != nil {
		return err
	}
	if ifModifiedSince != "" {
		// TODO: validate this string is in RFC1123Z format!
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
		m.writer.URIStart(uri, size, lastModified)
		md5Hash, err := m.download(resp.Body, filename)
		if err != nil {
			m.writer.FailURI(uri, err.Error())
			return err
		}
		m.writer.URIDone(uri, size, lastModified, md5Hash, filename, false)
	case 304:
		m.writer.URIDone(uri, size, lastModified, "", filename, true)
	default:
		err := fmt.Errorf("Error downloading: code %v %v", resp.StatusCode, resp.Status)
		m.writer.FailURI(uri, err.Error())
		return err
	}

	return nil
}

func (m *AptMethod) handleConfigure(msg *AptMessage) error {
	configs, ok := msg.Fields["Config-Item"]
	if !ok {
		return errors.New("No Config-Item in Configuration message")
	}
	for _, configItem := range configs {
		if strings.Contains(configItem, "Acquire::gar::Service-Account-JSON") {
			parts := strings.SplitN(configItem, "=", 2)
			if len(parts) != 2 {
				return errors.New(fmt.Sprintf("Invalid config item: %s", configItem))
			}
			m.config.ServiceAccountJSON = strings.TrimSpace(parts[1])
		}
		if strings.Contains(configItem, "Acquire::gar::Service-Account-Email") {
			parts := strings.SplitN(configItem, "=", 2)
			if len(parts) != 2 {
				return errors.New(fmt.Sprintf("Invalid config item: %s", configItem))
			}
			m.config.ServiceAccountEmail = strings.TrimSpace(parts[1])
		}
	}
	return nil
}

type AptMethodConfig struct {
	ServiceAccountJSON, ServiceAccountEmail string
}

type AptMessage struct {
	Code        int
	Description string
	Fields      map[string][]string
}

type AptMessageReader struct {
	reader  *bufio.Reader
	message *AptMessage
}

type AptMessageWriter struct {
	writer io.Writer
}

func (m *AptMessage) Get(key string) string {
	if vals, ok := m.Fields[key]; ok {
		if len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

func new100Message() *AptMessage {
	fields := make(map[string][]string)
	fields["Send-Config"] = []string{"True"}
	fields["Version"] = []string{"1.0"}
	return &AptMessage{Code: 100, Description: "Capabilities", Fields: fields}
}

func new101Message(msg string) *AptMessage {
	fields := make(map[string][]string)
	fields["Message"] = []string{msg}
	return &AptMessage{Code: 101, Description: "Log", Fields: fields}
}

func new200Message(uri, size, lastModified string) *AptMessage {
	fields := make(map[string][]string)
	fields["URI"] = []string{uri}
	fields["Size"] = []string{size}
	fields["Last-Modified"] = []string{lastModified}
	fields["Resume-Point"] = []string{"0"}
	return &AptMessage{Code: 200, Description: "URI Start", Fields: fields}
}

func new201Message(uri, size, lastModified, md5Hash, filename string, ims bool) *AptMessage {
	fields := make(map[string][]string)
	fields["URI"] = []string{uri}
	fields["Last-Modified"] = []string{lastModified}
	fields["Filename"] = []string{filename} // TODO: is this field needed?
	if ims {
		fields["IMS-Hit"] = []string{"true"}
	} else {
		fields["Size"] = []string{size}
		fields["MD5-Hash"] = []string{md5Hash}
	}
	return &AptMessage{Code: 201, Description: "URI Done", Fields: fields}
}

func new400Message(uri, msg string) *AptMessage {
	fields := make(map[string][]string)
	fields["URI"] = []string{uri}
	fields["Message"] = []string{msg}
	return &AptMessage{Code: 400, Description: "URI Failure", Fields: fields}
}

func new401Message(msg string) *AptMessage {
	fields := make(map[string][]string)
	fields["Message"] = []string{msg}
	return &AptMessage{Code: 401, Description: "General Failure", Fields: fields}
}

func NewAptMessageReader(r *bufio.Reader) *AptMessageReader {
	return &AptMessageReader{reader: r}
}

func NewAptMessageWriter(w io.Writer) *AptMessageWriter {
	return &AptMessageWriter{writer: w}
}

func (w *AptMessageWriter) WriteMessage(m *AptMessage) error {
	message := []string{fmt.Sprintf("%d %s", m.Code, m.Description)}
	for key, vals := range m.Fields {
		for _, val := range vals {
			message = append(message, fmt.Sprintf("%s: %s", key, val))
		}
	}
	message = append(message, "") // End with a newline.
	return w.WriteString(strings.Join(message, "\n"))
}

func (w *AptMessageWriter) WriteString(s string) error {
	if _, err := w.writer.Write([]byte(s)); err != nil {
		return err
	}
	return nil
}

func (w *AptMessageWriter) SendCapabilities() error {
	return w.WriteMessage(new100Message())
}

func (w *AptMessageWriter) Log(msg string) error {
	return w.WriteMessage(new101Message(msg))
}

func (w *AptMessageWriter) URIStart(uri, size, lastModified string) error {
	return w.WriteMessage(new200Message(uri, size, lastModified))
}

func (w *AptMessageWriter) URIDone(uri, size, lastModified, md5Hash, filename string, ims bool) error {
	return w.WriteMessage(new201Message(uri, size, lastModified, md5Hash, filename, ims))
}

func (w *AptMessageWriter) FailURI(uri, msg string) error {
	return w.WriteMessage(new400Message(uri, msg))
}

func (w *AptMessageWriter) Fail(msg string) error {
	return w.WriteMessage(new401Message(msg))
}

// ReadMessage reads lines from `reader` until a complete message is received.
func (r *AptMessageReader) ReadMessage() (*AptMessage, error) {
	for {
		line, err := r.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF || err == io.ErrClosedPipe {
				return nil, nil
			}
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
			if err := r.ParseHeader(line); err != nil {
				return nil, err
			}
		} else {
			if err := r.ParseField(line); err != nil {
				return nil, err
			}
		}
	}
}

func (r *AptMessageReader) ParseHeader(line string) error {
	if line == "" {
		return errors.New("Empty message header")
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
	r.message = &AptMessage{Code: code}
	return nil
}

func (r *AptMessageReader) ParseField(line string) error {
	if r.message == nil {
		return errors.New("Field parsed before header")
	}
	if line == "" {
		return errors.New("Empty message field")
	}
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return errors.New("Malformed field")
	}
	if r.message.Fields == nil {
		r.message.Fields = make(map[string][]string)
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	fieldlist := r.message.Fields[key]
	fieldlist = append(fieldlist, value)
	r.message.Fields[key] = fieldlist
	return nil
}
