package client

import (
	"errors"
	"strings"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	spec "github.com/PHPCraftdream/mcp-jack/spec"
)

func TestVerifyResponseVectors(t *testing.T) {
	vectors, err := spec.LoadResponseVectors()
	if err != nil {
		t.Fatalf("LoadResponseVectors failed: %v", err)
	}

	if len(vectors.Cases) == 0 {
		t.Fatalf("no response cases in fixture")
	}

	executed := 0

	for _, tc := range vectors.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			serverKey, err := jack.DecodeBase64URLFixed(tc.State.PinnedServerPublicKey, 32)
			if err != nil {
				t.Fatalf("decode server key: %v", err)
			}

			var headerValues []string
			for _, p := range tc.Response.Headers {
				if strings.EqualFold(p.Name, "Jack-Auth") {
					headerValues = append(headerValues, p.Value)
				}
			}

			body, err := tc.Response.Body()
			if err != nil {
				t.Fatalf("decode body: %v", err)
			}

			window := time.Duration(tc.State.WindowSeconds) * time.Second
			err = VerifyResponse(serverKey, tc.Response.Status, headerValues, tc.State.RequestSig, body, time.Unix(tc.State.Now, 0), window)

			var je *jack.Error

			switch tc.Expect.Result {
			case "accept":
				if err != nil {
					t.Errorf("case %s: got error %v, want accept", tc.ID, err)
				}
			case "reject":
				if err == nil {
					t.Errorf("case %s: got nil error, want reject with code %s", tc.ID, tc.Expect.Code)
				} else if !errors.As(err, &je) {
					t.Errorf("case %s: got error %v, not a *jack.Error", tc.ID, err)
				} else if je.Code != tc.Expect.Code {
					t.Errorf("case %s: got code %q, want code %q", tc.ID, je.Code, tc.Expect.Code)
				} else if je.HTTPStatus != 0 {
					// Spec 01 section 5 assigns no HTTP status to client-side verification failures.
					t.Errorf("case %s: HTTPStatus = %d, want 0", tc.ID, je.HTTPStatus)
				}
			default:
				t.Errorf("case %s: unknown expect result %q", tc.ID, tc.Expect.Result)
			}
		})

		executed++
	}

	if executed == 0 {
		t.Fatalf("no response cases executed")
	}
	t.Logf("executed %d response cases", executed)
}

func TestVerifyResponseDefaultWindow(t *testing.T) {
	vectors, err := spec.LoadResponseVectors()
	if err != nil {
		t.Fatalf("LoadResponseVectors failed: %v", err)
	}

	var tc *spec.ResponseCase
	for i := range vectors.Cases {
		if vectors.Cases[i].ID == "res-accept" {
			tc = &vectors.Cases[i]
			break
		}
	}
	if tc == nil {
		t.Fatalf("res-accept case not found")
	}

	serverKey, err := jack.DecodeBase64URLFixed(tc.State.PinnedServerPublicKey, 32)
	if err != nil {
		t.Fatalf("decode server key: %v", err)
	}

	var headerValues []string
	for _, p := range tc.Response.Headers {
		if strings.EqualFold(p.Name, "Jack-Auth") {
			headerValues = append(headerValues, p.Value)
		}
	}

	body, err := tc.Response.Body()
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}

	if err := VerifyResponse(serverKey, tc.Response.Status, headerValues, tc.State.RequestSig, body, time.Unix(tc.State.Now+30, 0), 0); err != nil {
		t.Errorf("window <= 0 at +30s boundary: got error %v, want accept", err)
	}

	var je *jack.Error
	if err := VerifyResponse(serverKey, tc.Response.Status, headerValues, tc.State.RequestSig, body, time.Unix(tc.State.Now+31, 0), 0); err == nil {
		t.Errorf("window <= 0 at +31s: got nil error, want timestamp_out_of_window")
	} else if !errors.As(err, &je) {
		t.Errorf("window <= 0 at +31s: got error %v, not a *jack.Error", err)
	} else if je.Code != "timestamp_out_of_window" {
		t.Errorf("window <= 0 at +31s: got code %q, want timestamp_out_of_window", je.Code)
	}
}
