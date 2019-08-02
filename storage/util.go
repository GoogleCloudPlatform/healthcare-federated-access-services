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
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

var (
	secretParams = map[string]bool{
		"clientSecret":  true,
		"client_secret": true,
		"code":          true,
		"link_token":    true,
		"redirect_uri":  true,
	}
)

func MakeConfigHistory(desc, resType string, rev int64, ts float64, r *http.Request, user string, orig, update proto.Message) proto.Message {
	path := ""
	query := ""
	method := ""
	if r != nil {
		path = r.URL.Path
		method = r.Method
		first := true
		for name, values := range r.URL.Query() {
			if first {
				first = false
			} else {
				query += "&"
			}
			value := strings.Join(values, ",")
			if _, ok := secretParams[name]; ok {
				value = "***"
			}
			// TODO: escape name and value
			query += name + "=" + value
		}
	}
	m := jsonpb.Marshaler{}
	ov, _ := m.MarshalToString(orig)
	uv, _ := m.MarshalToString(update)

	return &pb.HistoryEntry{
		Revision:      rev,
		User:          user,
		CommitTime:    ts,
		Path:          path,
		Query:         query,
		Desc:          desc,
		Method:        method,
		ChangeType:    resType,
		OriginalValue: ov,
		ChangeRequest: uv,
	}
}

func GetHistory(store Store, datatype, realm, user, id string, r *http.Request) (*pb.History, int, error) {
	hlist := make([]proto.Message, 0)
	if err := store.ReadHistory(datatype, realm, user, id, &hlist); err != nil {
		if os.IsNotExist(err) {
			// TODO: perhaps this should be the empty list?
			return nil, http.StatusBadRequest, fmt.Errorf("no config history available")
		}
		return nil, http.StatusBadRequest, fmt.Errorf("service storage unavailable: %v, retry later", err)
	}
	he := make([]*pb.HistoryEntry, len(hlist))
	var ok bool
	for i, e := range hlist {
		he[i], ok = e.(*pb.HistoryEntry)
		if !ok {
			return nil, http.StatusInternalServerError, fmt.Errorf("cannot load history entry %d", i)
		}
	}
	history := &pb.History{
		History: he,
	}
	pageToken := r.URL.Query().Get("pageToken")
	start, err := strconv.ParseInt(pageToken, 10, 64)
	if err != nil {
		start = 0
	}

	pageSize := r.URL.Query().Get("pageSize")
	size, err := strconv.ParseInt(pageSize, 10, 64)
	if err != nil || size < 1 {
		size = 50
	}
	if size > 1000 {
		size = 1000
	}
	// Reverse order
	a := history.History
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}

	for i, entry := range history.History {
		if entry.Revision <= start {
			history.History = history.History[i:]
			break
		}
	}
	if len(history.History) > int(size) {
		history.NextPageToken = fmt.Sprintf("%d", history.History[size].Revision)
		history.History = history.History[:size]
	}
	return history, http.StatusOK, nil
}
