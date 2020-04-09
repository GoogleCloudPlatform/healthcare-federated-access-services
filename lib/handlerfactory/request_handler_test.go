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

package handlerfactory

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakestore" /* copybara-comment: fakestore */

	glog "github.com/golang/glog" /* copybara-comment */
	dpb "github.com/golang/protobuf/ptypes/duration" /* copybara-comment */
)

var varsRE = map[string]*regexp.Regexp{
	"duration": regexp.MustCompile("/durations/([^/]*)"),
}

func extractVarsFake(r *http.Request) map[string]string {
	vars := make(map[string]string)
	for name, re := range varsRE {
		m := re.FindStringSubmatch(r.URL.Path)
		if len(m) < 2 {
			continue
		}
		vars[name] = m[1]
	}
	return vars
}

func Test_HTTPHandler_Get(t *testing.T) {
	extractVars = extractVarsFake

	s := fakestore.New()
	hf := &Options{
		TypeName:            "duration",
		NameField:           "duration",
		PathPrefix:          "durations/{duration}",
		HasNamedIdentifiers: true,
		NameChecker:         map[string]*regexp.Regexp{"duration": regexp.MustCompile(".*")},
		Service:             &fakeService{store: s},
	}
	h := MakeHandler(s, hf)

	err := s.Write("resource", "master", "user", "fake-duration-id", storage.LatestRev, &dpb.Duration{Seconds: 60}, nil)
	if err != nil {
		t.Errorf("store.Write() failed: %v", err)
	}

	req := httputils.MustNewReq(http.MethodGet, "https://example.org/durations/fake-duration-id", nil)
	got := httputils.NewFakeWriter()
	h.ServeHTTP(got, req)

	want := &httputils.FakeWriter{
		Headers: http.Header{
			"Access-Control-Allow-Headers": {"Content-Type, Origin, Accept, Authorization, X-Link-Authorization"},
			"Access-Control-Allow-Methods": {"GET,POST,PUT,PATCH,DELETE,OPTIONS"},
			"Access-Control-Allow-Origin":  {"*"},
			"Content-Type":                 {"application/json"},
		},
		Body: `"60s"`,
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("ServeHTTP(w,r); diff (-want +got):\n%s", diff)
	}
}

func Test_HTTPHandler_Get_NotFound(t *testing.T) {
	extractVars = extractVarsFake

	s := fakestore.New()
	hf := &Options{
		TypeName:            "duration",
		NameField:           "duration",
		PathPrefix:          "durations/{duration}",
		HasNamedIdentifiers: true,
		NameChecker:         map[string]*regexp.Regexp{"duration": regexp.MustCompile(".*")},
		Service:             &fakeService{store: s},
	}
	h := MakeHandler(s, hf)

	req := httputils.MustNewReq(http.MethodGet, "https://example.org/durations/fake-duration-id", nil)
	got := httputils.NewFakeWriter()
	h.ServeHTTP(got, req)

	want := &httputils.FakeWriter{
		Headers: http.Header{
			"Access-Control-Allow-Headers": {"Content-Type, Origin, Accept, Authorization, X-Link-Authorization"},
			"Access-Control-Allow-Methods": {"GET,POST,PUT,PATCH,DELETE,OPTIONS"},
			"Access-Control-Allow-Origin":  {"*"},
			"Content-Type":                 {"application/json"},
		},
		Body: `{"code":5,"message":"duration not found: \"fake-duration-id\""}`,
		Code: http.StatusNotFound,
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("ServeHTTP(w,r); diff (-want +got):\n%s", diff)
	}
}

func Test_HTTPHandler_Post(t *testing.T) {
	extractVars = extractVarsFake

	s := fakestore.New()
	hf := &Options{
		TypeName:            "duration",
		NameField:           "duration",
		PathPrefix:          "durations/{duration}",
		HasNamedIdentifiers: true,
		NameChecker:         map[string]*regexp.Regexp{"duration": regexp.MustCompile(".*")},
		Service:             &fakeService{store: s},
	}
	h := MakeHandler(s, hf)

	req := httputils.MustNewReq(http.MethodPost, "https://example.org/durations/fake-duration-id", httputils.MustEncodeProto(&dpb.Duration{Seconds: 60}))
	got := httputils.NewFakeWriter()
	h.ServeHTTP(got, req)

	want := &httputils.FakeWriter{
		Headers: http.Header{
			"Access-Control-Allow-Headers": {"Content-Type, Origin, Accept, Authorization, X-Link-Authorization"},
			"Access-Control-Allow-Methods": {"GET,POST,PUT,PATCH,DELETE,OPTIONS"},
			"Access-Control-Allow-Origin":  {"*"},
			"Content-Type":                 {"application/json"},
		},
		Body: `"60s"`,
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("ServeHTTP(w,r); diff (-want +got):\n%s", diff)
	}

	sgot := &dpb.Duration{}
	err := s.Read("resource", "master", "user", "fake-duration-id", storage.LatestRev, sgot)
	if err != nil {
		t.Fatalf("store.Read() failed: %v", err)
	}
	swant := &dpb.Duration{Seconds: 60}
	if diff := cmp.Diff(sgot, swant, protocmp.Transform()); diff != "" {
		t.Errorf("store.Read() diff (-want +got):\n%s", diff)
	}
}

func Test_HTTPHandler_Delete(t *testing.T) {
	extractVars = extractVarsFake

	s := fakestore.New()

	hf := &Options{
		TypeName:            "duration",
		NameField:           "duration",
		PathPrefix:          "durations/{duration}",
		HasNamedIdentifiers: true,
		NameChecker:         map[string]*regexp.Regexp{"duration": regexp.MustCompile(".*")},
		Service:             &fakeService{store: s},
	}
	h := MakeHandler(s, hf)

	err := s.Write("resource", "master", "user", "fake-duration-id", storage.LatestRev, &dpb.Duration{Seconds: 60}, nil)
	if err != nil {
		t.Errorf("store.Write() failed: %v", err)
	}

	req := httputils.MustNewReq(http.MethodDelete, "https://example.org/durations/fake-duration-id", nil)
	got := httputils.NewFakeWriter()
	h.ServeHTTP(got, req)

	want := &httputils.FakeWriter{
		Headers: http.Header{},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("ServeHTTP(w,r); diff (-want +got):\n%s", diff)
	}
}

type fakeService struct {
	store *fakestore.Store

	// TODO: cleanup these and pass them explicitly to the methods.
	tx *fakestore.Tx
}

func (s *fakeService) Setup(r *http.Request, tx storage.Tx) (int, error) {
	glog.Infof("Setup: tx = %+v", tx)

	ntx, ok := tx.(*fakestore.Tx)
	if !ok {
		return http.StatusInternalServerError, status.Error(codes.Internal, "invalid transaction type")
	}
	s.tx = ntx
	return http.StatusOK, nil
}

func (s *fakeService) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	glog.Infof("NormalizeInput: name = %v vars = %+v", name, vars)
	return nil
}

func (s *fakeService) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	glog.Infof("LookupItem: name = %v vars = %+v", name, vars)
	ok, err := s.store.Exists("resource", "master", "user", vars["duration"], storage.LatestRev)
	if err != nil {
		return false
	}
	return ok
}

func (s *fakeService) Get(r *http.Request, name string) (proto.Message, error) {
	vars := extractVars(r)
	glog.Infof("Get: name = %v vars = %+v", name, vars)
	d := &dpb.Duration{}
	err := s.store.ReadTx("resource", "master", "user", vars["duration"], storage.LatestRev, d, s.tx)
	glog.Infof("ReadTx() = %+v, %v", d, err)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (s *fakeService) Post(r *http.Request, name string) (proto.Message, error) {
	vars := extractVars(r)
	glog.Infof("Post: name = %v vars = %+v", name, vars)
	d := &dpb.Duration{}
	if err := httputils.DecodeProtoReq(d, r); err != nil {
		return nil, err
	}
	err := s.store.WriteTx("resource", "master", "user", vars["duration"], storage.LatestRev, d, nil, s.tx)
	glog.Infof("WriteTx() = %+v", err)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (s *fakeService) Put(r *http.Request, name string) (proto.Message, error) {
	// TODO
	return nil, nil
}

func (s *fakeService) Patch(r *http.Request, name string) (proto.Message, error) {
	// TODO
	return nil, nil
}

func (s *fakeService) Remove(r *http.Request, name string) (proto.Message, error) {
	vars := extractVars(r)
	glog.Infof("Remove: name = %v vars = %+v", name, vars)
	err := s.store.DeleteTx("resource", "master", "user", vars["duration"], storage.LatestRev, s.tx)
	glog.Infof("DeleteTx() = %+v", err)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *fakeService) CheckIntegrity(r *http.Request) *status.Status {
	return nil
}

func (s *fakeService) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return tx.Finish()
}

func TestEmptyService(t *testing.T) {
	extractVars = extractVarsFake

	s := fakestore.New()
	hf := &Options{
		TypeName:            "duration",
		NameField:           "duration",
		PathPrefix:          "durations/{duration}",
		HasNamedIdentifiers: true,
		NameChecker:         map[string]*regexp.Regexp{"duration": regexp.MustCompile(".*")},
		Service:             &Empty{},
	}
	h := MakeHandler(s, hf)

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

	for _, m := range methods {
		t.Run(m, func(t *testing.T) {
			r := httputils.MustNewReq(m, "https://example.org/durations/fake-duration-id", httputils.MustEncodeProto(&dpb.Duration{Seconds: 60}))
			w := httputils.NewFakeWriter()
			h.ServeHTTP(w, r)

			if w.Code != http.StatusNotFound {
				t.Errorf("code = %d, wants %d", w.Code, http.StatusNotFound)
			}

			bodyContain := m + " /durations/fake-duration-id not exist"
			if !strings.Contains(w.Body, bodyContain) {
				t.Errorf("body = %s, wants contains(%s)", w.Body, bodyContain)
			}
		})
	}
}

func TestSetupError(t *testing.T) {
	extractVars = extractVarsFake

	s := fakestore.New()
	hf := &Options{
		TypeName:            "duration",
		NameField:           "duration",
		PathPrefix:          "durations/{duration}",
		HasNamedIdentifiers: true,
		NameChecker:         map[string]*regexp.Regexp{"duration": regexp.MustCompile(".*")},
		Service:             &serviceSetupErr{},
	}
	h := MakeHandler(s, hf)

	r := httputils.MustNewReq(http.MethodPost, "https://example.org/durations/fake-duration-id", httputils.MustEncodeProto(&dpb.Duration{Seconds: 60}))
	w := httputils.NewFakeWriter()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, wants %d", w.Code, http.StatusUnauthorized)
	}
}

type serviceSetupErr struct {
	Empty
}

func (s *serviceSetupErr) Setup(r *http.Request, tx storage.Tx) (int, error) {
	return 0, status.Error(codes.Unauthenticated, "error")
}

func TestCrash(t *testing.T) {
	extractVars = extractVarsFake

	s := fakestore.New()
	hf := &Options{
		TypeName:            "duration",
		NameField:           "duration",
		PathPrefix:          "durations/{duration}",
		HasNamedIdentifiers: true,
		NameChecker:         map[string]*regexp.Regexp{"duration": regexp.MustCompile(".*")},
		Service:             &serviceGetCrash{},
	}
	h := MakeHandler(s, hf)

	r := httputils.MustNewReq(http.MethodGet, "https://example.org/durations/fake-duration-id", httputils.MustEncodeProto(&dpb.Duration{Seconds: 60}))
	w := httputils.NewFakeWriter()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("code = %d, wants %d", w.Code, http.StatusInternalServerError)
	}
}

type serviceGetCrash struct {
	Empty
}

func (s *serviceGetCrash) Get(r *http.Request, name string) (proto.Message, error) {
	a := []string{}
	// crash, access index of slice out of range.
	fmt.Println(a[1])
	return nil, nil
}
