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

package fakestore

import (
	"time"

	"github.com/golang/protobuf/proto" /* copybara-comment */
)

// Key is the type of keys.
type Key struct {
	Datatype string
	Realm    string
	User     string
	ID       string
	Rev      string
}

// Value is the type of values.
type Value proto.Message

// Data is the type of data items.
// Maps keys to their values.
type Data map[Key]Value

func copyData(src Data) Data {
	dst := make(Data)
	for k, v := range src {
		dst[k] = proto.Clone(v)
	}
	return dst
}

// State is the type containing the data in the store.
type State struct {
	// Version is a UUID that can be used to check if Data has changed.
	Version string

	// LastCommit is the timestamp for the last commit.
	// Useful for troubleshooting.
	LastCommit time.Time

	// Date enteries.
	Data Data

	// History entries.
	History Data
}

func copyState(src State) State {
	dst := State{
		Version:    src.Version,
		LastCommit: src.LastCommit,
		Data:       copyData(src.Data),
		History:    copyData(src.History),
	}
	return dst
}

// KV is the type of a (Key,Value) pair.
// Used for sorting.
type KV struct {
	K Key
	V Value
}

// KVList is the type of list of (Key,Value) pairs.
// Used for sorting. Implements sort.Interface.
type KVList []KV

// Len is the number of elements in the collection.
func (s KVList) Len() int {
	return len(s)
}

// Swap swaps the elements with indexes i and j.
func (s KVList) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less reports whether the element with
// index i should sort before the element with index j.
func (s KVList) Less(i, j int) bool {
	switch {
	case s[i].K.Datatype > s[j].K.Datatype:
		return false
	case s[i].K.Datatype < s[j].K.Datatype:
		return true

	// The previous ones are equal.
	case s[i].K.Realm > s[j].K.Realm:
		return false
	case s[i].K.Realm < s[j].K.Realm:
		return true

	// The previous ones are equal.
	case s[i].K.User > s[j].K.User:
		return false
	case s[i].K.User < s[j].K.User:
		return true

	// The previous ones are equal.
	case s[i].K.ID > s[j].K.ID:
		return false
	case s[i].K.ID < s[j].K.ID:
		return true

	// The previous ones are equal.
	// Revisions are in reverse order.
	case s[i].K.Rev < s[j].K.Rev:
		return true
	case s[i].K.Rev > s[j].K.Rev:
		return false

	// All compared fields are are equal.
	default:
		return false
	}
}
