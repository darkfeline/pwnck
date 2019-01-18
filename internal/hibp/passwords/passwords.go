// Copyright (C) 2019  Allen Li
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package passwords wraps the Pwned Passwords API.
//
// https://haveibeenpwned.com/API/v2#PwnedPasswords
package passwords

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"go.felesatra.moe/go2/errors"
)

const rangeURL = `https://api.pwnedpasswords.com/range/`

type Match struct {
	Digest string
	Count  int
}

const (
	sha1DigestLength  = 40
	rangePrefixLength = 5
	rangeDigestLength = sha1DigestLength - rangePrefixLength
)

type Client interface {
	Get(url string) (*http.Response, error)
}

func Range(c Client, hash string) ([]Match, error) {
	if len(hash) < rangePrefixLength {
		return nil, fmt.Errorf("passwords range %s: hash too short", hash)
	}
	hash = strings.ToUpper(hash[:rangePrefixLength])
	resp, err := c.Get(rangeURL + hash)
	if err != nil {
		return nil, errors.Wrapf(err, "passwords range %s", hash)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("passwords range %s: GET %d", hash, resp.StatusCode)
	}
	m, err := parseRangeResponse(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "passwords range %s", hash)
	}
	for i := range m {
		m[i].Digest = hash + m[i].Digest
	}
	return m, nil
}

func parseRangeResponse(r io.Reader) ([]Match, error) {
	s := bufio.NewScanner(r)
	var m []Match
	for s.Scan() {
		line := s.Text()
		// Must be at least length of digest + ":1".
		if len(line) < rangeDigestLength+2 {
			return nil, fmt.Errorf("bad response line %s", line)
		}
		n, err := strconv.Atoi(line[rangeDigestLength+1:])
		if err != nil {
			return nil, fmt.Errorf("bad response line %s", line)
		}
		m = append(m, Match{
			Digest: line[:rangeDigestLength],
			Count:  n,
		})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return m, nil
}
