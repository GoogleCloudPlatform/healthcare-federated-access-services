package common

import (
	"net/http/httptest"
	"testing"

	"google3/third_party/hcls_federated_access/common/models/models"
)

func assertHeader(t *testing.T, w *httptest.ResponseRecorder, header string, expect string) {
	if w.Header().Get(header) != expect {
		t.Errorf("Wants header %q is %q, Got %q", header, expect, w.Header().Get(header))
	}
}

func TestSendResponse(t *testing.T) {
	w := httptest.NewRecorder()

	msg := &models.LoginState{}

	err := SendResponse(msg, w)
	if err != nil {
		t.Fatalf("SendResponse failed. %q", err)
	}

	assertHeader(t, w, "Content-Type", "application/json")
	assertHeader(t, w, "Cache-Control", "no-store")
	assertHeader(t, w, "Pragma", "no-cache")
	assertHeader(t, w, "Access-Control-Allow-Origin", "*")
	assertHeader(t, w, "Access-Control-Allow-Headers", "Content-Type, Origin, Accept, Authorization")
	assertHeader(t, w, "Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
}
