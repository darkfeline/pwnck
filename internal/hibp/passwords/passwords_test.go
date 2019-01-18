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

package passwords

import (
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type fakeClient struct {
	body string
}

type readCloser struct {
	io.Reader
}

func (readCloser) Close() error {
	return nil
}

func (c fakeClient) Get(url string) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       readCloser{strings.NewReader(c.body)},
	}, nil
}

func TestRange(t *testing.T) {
	t.Parallel()
	c := fakeClient{
		body: `0018A45C4D1DEF81644B54AB7F969B88D65:1`,
	}
	got, err := Range(c, "ABCDE")
	if err != nil {
		t.Fatalf("Range returned error %s", err)
	}
	want := []Match{
		{Digest: "ABCDE0018A45C4D1DEF81644B54AB7F969B88D65", Count: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Range = %#v; want %#v", got, want)
	}
}

func TestParseRangeResponse(t *testing.T) {
	t.Parallel()
	body := strings.NewReader(`0018A45C4D1DEF81644B54AB7F969B88D65:1
00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
011053FD0102E94D6AE2F8B83D76FAF94F6:1
`)
	got, err := parseRangeResponse(body)
	if err != nil {
		t.Fatalf("parseRangeResponse returned error %s", err)
	}
	want := []Match{
		{Digest: "0018A45C4D1DEF81644B54AB7F969B88D65", Count: 1},
		{Digest: "00D4F6E8FA6EECAD2A3AA415EEC418D38EC", Count: 2},
		{Digest: "011053FD0102E94D6AE2F8B83D76FAF94F6", Count: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseRangeResponse = %#v; want %#v", got, want)
	}
}
