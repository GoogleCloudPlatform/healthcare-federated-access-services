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

package storage

import (
	"github.com/golang/protobuf/proto" /* copybara-comment */
)

type StorageCache struct {
	entityCache  map[string]proto.Message
	historyCache map[string][]proto.Message
	backup       *StorageCache
}

func NewStorageCache() *StorageCache {
	return &StorageCache{
		entityCache:  make(map[string]proto.Message),
		historyCache: make(map[string][]proto.Message),
	}
}

func (s *StorageCache) GetEntity(id string) (proto.Message, bool) {
	// TODO: expire cache entries.
	msg, ok := s.entityCache[id]
	return msg, ok
}

func (s *StorageCache) PutEntity(id string, msg proto.Message) {
	// TODO: cap cache memory size.
	s.entityCache[id] = msg
}

func (s *StorageCache) DeleteEntity(id string) {
	if _, ok := s.entityCache[id]; ok {
		delete(s.entityCache, id)
	}
}

func (s *StorageCache) GetHistory(id string) ([]proto.Message, bool) {
	// TODO: expire cache entries.
	msg, ok := s.historyCache[id]
	return msg, ok
}

func (s *StorageCache) PutHistory(id string, msg []proto.Message) {
	// TODO: cap cache memory size.
	s.historyCache[id] = msg
}

func (s *StorageCache) DeleteHistory(id string) {
	if _, ok := s.historyCache[id]; ok {
		delete(s.historyCache, id)
	}
}

func (s *StorageCache) Backup() {
	cp := NewStorageCache()
	for k, v := range s.entityCache {
		cp.entityCache[k] = proto.Clone(v)
	}
	for k, v := range s.historyCache {
		list := make([]proto.Message, len(v))
		for i, msg := range v {
			if msg != nil {
				list[i] = proto.Clone(msg)
			}
		}
		cp.historyCache[k] = list
	}
	s.backup = cp
}

func (s *StorageCache) Restore() {
	if s.backup == nil {
		return
	}
	s.entityCache = s.backup.entityCache
	s.historyCache = s.backup.historyCache
	s.backup = nil
}
