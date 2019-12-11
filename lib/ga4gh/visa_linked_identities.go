// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ga4gh

import (
	"fmt"
	"net/url"
	"strings"

	glog "github.com/golang/glog" /* copybara-comment */
)

// ID identifies a subject at an issuer.
type ID struct {
	Issuer  string
	Subject string
}

// CheckLinkedIDs checks if there are sufficient LinkedIdentities Assertions to
// show that all IDs of the given list of Visas are the same.
func CheckLinkedIDs(vs []*Visa) error {
	var ids []ID
	for _, v := range vs {
		ids = append(ids, ID{v.Data().Issuer, v.Data().Subject})
	}

	// links contains which ids are linked together.
	links := make(map[ID][]ID)
	for _, v := range vs {
		x := ID{v.Data().Issuer, v.Data().Subject}
		for _, y := range ExtractLinkedIDs(v.Data().Assertion) {
			links[x] = append(links[x], y)
			links[y] = append(links[y], x)
		}
	}
	return connectedIDs(ids, links)
}

func connectedIDs(ids []ID, links map[ID][]ID) error {
	glog.V(1).Infof("connectedIDs(%+v,%+v)", ids, links)

	if len(ids) < 2 {
		return nil
	}
	// BFS
	mark := make(map[ID]bool)
	queue := make(chan ID, len(ids))
	defer close(queue)
	queue <- ids[0]
	for len(queue) > 0 {
		x := <-queue
		mark[x] = true
		for _, y := range links[x] {
			if !mark[y] {
				queue <- y
			}
		}
	}
	if len(mark) != len(ids) {
		return fmt.Errorf("identities on the visas are not connected")
	}
	return nil
}

// ExtractLinkedIDs extracts ids from a LinkedIdentities Assertion. Format is a
// semicolon separated list, each item in the list is of the form "subject,issuer"
// where subject and issuer are URI-encoded.
// http://bit.ly/ga4gh-passport-v1#linkedidentities
func ExtractLinkedIDs(a Assertion) []ID {
	glog.V(1).Info("ExtractLinkedIDs")

	if a.Type != LinkedIdentities {
		return nil
	}
	items := strings.Split(string(a.Value), ";")

	var res []ID
	for _, item := range items {
		parts := strings.Split(item, ",")
		if len(parts) != 2 {
			glog.Warningf("invalid value for LinkedIdentities assertion: %+v", a.Value)
			return nil
		}

		issuer, err := url.PathUnescape(parts[1])
		if err != nil {
			glog.Warningf("invalid value for LinkedIdentities assertion: %+v", a.Value)
			return nil
		}
		subject, err := url.PathUnescape(parts[0])
		if err != nil {
			glog.Warningf("invalid value for LinkedIdentities assertion: %+v", a.Value)
			return nil
		}

		res = append(res, ID{Issuer: issuer, Subject: subject})
	}
	return res
}

// LinkedIDValue creates a LinkedIdentities Assertion Value from a given list of
// IDs.
func LinkedIDValue(neighbors []ID) Value {
	glog.V(1).Info("LinkedIDValue")
	var ids []string
	for _, n := range neighbors {
		ids = append(ids, url.PathEscape(n.Subject)+","+url.PathEscape(n.Issuer))
	}
	return Value(strings.Join(ids, ";"))
}
