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
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var newlineRegexp = regexp.MustCompile(`\r?\n`)

// Message represents a single RFC822 Apt message.
type Message struct {
	code        int
	description string
	fields      map[string][]string
}

// Get returns the first AptMessage Field for `key`, or "".
func (m *Message) Get(key string) string {
	if vals, ok := m.fields[key]; ok {
		if len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

func (m *Message) String() string {
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
			// Messages are allowed to contain newlines, but they must not contain double newlines,
			// nor end in a newline (since this would result in a premature double newline). We'll
			// encode all newlines here as \n for simplicity.
			val = newlineRegexp.ReplaceAllString(val, "\\n")

			message = append(message, fmt.Sprintf("%s: %s", key, val))
		}
	}
	message = append(message, "")
	message = append(message, "") // End with a newline.
	return strings.Join(message, "\n")
}

func new100Message() Message {
	fields := make(map[string][]string)
	fields["Send-Config"] = []string{"true"}
	fields["Version"] = []string{"1.0"}
	return Message{code: 100, description: "Capabilities", fields: fields}
}

func new101Message(msg string) Message {
	fields := make(map[string][]string)
	fields["Message"] = []string{msg}
	return Message{code: 101, description: "Log", fields: fields}
}

func new200Message(uri, size, lastModified string) Message {
	fields := make(map[string][]string)
	fields["URI"] = []string{uri}
	fields["Size"] = []string{size}
	if lastModified != "" {
		fields["Last-Modified"] = []string{lastModified}
	}
	fields["Resume-Point"] = []string{"0"}
	return Message{code: 200, description: "URI Start", fields: fields}
}

func new201Message(uri, size, lastModified, md5Hash, filename string, imsHit bool) Message {
	fields := make(map[string][]string)
	fields["URI"] = []string{uri}
	fields["Last-Modified"] = []string{lastModified}
	fields["Filename"] = []string{filename}
	if imsHit {
		fields["IMS-Hit"] = []string{"true"}
	} else {
		fields["Size"] = []string{size}
		fields["MD5-Hash"] = []string{md5Hash}
	}
	return Message{code: 201, description: "URI Done", fields: fields}
}

func new400Message(uri, msg string) Message {
	fields := make(map[string][]string)
	fields["URI"] = []string{uri}
	fields["Message"] = []string{msg}
	return Message{code: 400, description: "URI Failure", fields: fields}
}

func new401Message(msg string) Message {
	fields := make(map[string][]string)
	fields["Message"] = []string{msg}
	return Message{code: 401, description: "General Failure", fields: fields}
}
