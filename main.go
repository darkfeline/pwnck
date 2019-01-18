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

// Command pwnck checks passwords against Have I Been Pwned.
//
// Passwords should be fed into stdin, one per line.  Pwned passwords
// are echoed to stdout, one per line.
//
// Please verify the source code before sending your passwords to any
// software.
package main

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"log"
	"net/http"
	"os"

	"go.felesatra.moe/pwnck/internal/hibp/passwords"
)

func main() {
	log.SetPrefix("pwck: ")
	errs := false
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		pw := s.Text()
		count, err := passwordIsPwned(pw)
		if err != nil {
			log.Print(err)
			errs = true
		}
		if count > 0 {
			fmt.Printf("%s:%d\n", pw, count)
		}
	}
	if err := s.Err(); err != nil {
		log.Print(err)
		errs = true
	}
	if errs {
		os.Exit(1)
	}
}

func passwordIsPwned(pw string) (int, error) {
	digest := sha1.Sum([]byte(pw))
	hexdigest := fmt.Sprintf("%X", digest)
	m, err := passwords.Range(http.DefaultClient, hexdigest)
	if err != nil {
		return 0, err
	}
	for _, m := range m {
		if m.Digest == hexdigest {
			return m.Count, nil
		}
	}
	return 0, nil
}
