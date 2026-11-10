package server

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const maxDurableTimestamp int64 = 999999999999

// AdmissionStateStore сериализует callback со всеми изменениями registry.
// Callback вызывается синхронно ровно один раз; не вызывает state, handler или проверку подписи.
// Внешний store обязан обеспечить тот же gate для каждого своего writer.
type AdmissionStateStore interface {
	StateStore
	WithAdmission(kid string, check func(RegistryEntry, bool) error) error
}

func (s *MemoryState) WithAdmission(kid string, check func(RegistryEntry, bool) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, known := lookupKey(s.keys, kid)
	return check(entry, known)
}

func (s *FileState) WithAdmission(kid string, check func(RegistryEntry, bool) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, known := lookupKey(s.keys, kid)
	return check(entry, known)
}

// NonceAdmission передаётся только после успешной проверки подписи.
// Backend не сохраняет Now/Validate и не вызывает их после Reserve.
type NonceAdmission struct {
	KID          string
	Nonce        string
	Signature    string
	SigningBytes string
	Timestamp    int64
	Window       int64
	Now          func() int64
	Validate     func(int64) bool
}

// NonceReceipt подтверждает точную final reservation, не только подготовку intent.
type NonceReceipt struct {
	Version         uint32
	DeploymentID    string
	StoreGeneration uint64
	OwnerGeneration uint64
	IntentID        string
	OperationID     [16]byte
	KID             string
	Nonce           string
	Signature       string
	RequestHash     string
	Timestamp       int64
	RetainUntil     int64
	HighWater       int64
}

// NonceLease удерживает serving epoch до завершения запроса.
// Valid атомарно проверяет owner/generation/fence; Release идемпотентен.
type NonceLease interface {
	Valid() bool
	Release()
}

// DurableNonceStore — доверенная application-owned transactional граница.
// Успех разрешён только после подтверждённого durable final commit.
// Ошибка/unknown не допускают dispatch, retry или подмену операции.
// Fence немедленно закрывает admission; uncertain persistence требует dirty startup gate.
// Реальная durability и lifetime-exclusive ownership обеспечиваются backend, не интерфейсом.
type DurableNonceStore interface {
	Reserve(NonceAdmission) (NonceReceipt, NonceLease, *jack.Error)
	Fence()
}

type admissionLease struct {
	once  sync.Once
	lease NonceLease
}

// Done освобождает lease; прямой caller Verify обязан вызвать Done после обработки.
// NewHandler вызывает Done автоматически, включая native/error ветки.
func (r Result) Done() {
	if r.admission != nil {
		r.admission.once.Do(r.admission.lease.Release)
	}
}

// NonceIntentID строит точную storage identity из candidate durable-nonce spec.
func NonceIntentID(deployment string, admission NonceAdmission, operation [16]byte) (string, error) {
	if !utf8.ValidString(deployment) || len(deployment) == 0 || len(deployment) > 1024 {
		return "", errors.New("server: invalid deployment identity")
	}
	kid, err := jack.DecodeBase64URLFixed(admission.KID, 32)
	if err != nil {
		return "", err
	}
	nonce, err := jack.DecodeBase64URLFixed(admission.Nonce, 16)
	if err != nil {
		return "", err
	}
	sig, err := jack.DecodeBase64URLFixed(admission.Signature, 64)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("mcp-jack/durable-nonce/intent/v1\n"))
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(deployment)))
	h.Write(size[:])
	h.Write([]byte(deployment))
	h.Write(kid)
	h.Write(nonce)
	h.Write(sig)
	signingHash := sha256.Sum256([]byte(admission.SigningBytes))
	h.Write(signingHash[:])
	h.Write(operation[:])
	return jack.EncodeBase64URL(h.Sum(nil)), nil
}

func receiptMatches(receipt NonceReceipt, request NonceAdmission) bool {
	intent, err := NonceIntentID(receipt.DeploymentID, request, receipt.OperationID)
	return err == nil && receipt.Version == 1 && receipt.StoreGeneration > 0 && receipt.OwnerGeneration > 0 &&
		receipt.IntentID == intent && receipt.KID == request.KID && receipt.Nonce == request.Nonce &&
		receipt.Signature == request.Signature && receipt.RequestHash == jack.BodyHash([]byte(request.SigningBytes)) &&
		receipt.Timestamp == request.Timestamp && receipt.RetainUntil == request.Timestamp+request.Window &&
		receipt.HighWater >= 0 && receipt.HighWater <= maxDurableTimestamp &&
		receipt.HighWater-request.Timestamp <= request.Window && request.Timestamp-receipt.HighWater <= request.Window
}

func sameEntry(a, b RegistryEntry) bool {
	sameTime := func(x, y *int64) bool {
		return (x == nil && y == nil) || (x != nil && y != nil && *x == *y)
	}
	return a.Kid == b.Kid && a.PublicKey == b.PublicKey && a.Name == b.Name && a.Admin == b.Admin &&
		sameTime(a.NotBefore, b.NotBefore) && sameTime(a.NotAfter, b.NotAfter)
}

func durableFailure() *jack.Error {
	return &jack.Error{HTTPStatus: 503, Code: "durability_unavailable", Message: "durable admission is unavailable"}
}

func definiteStorageRefusal(err *jack.Error) bool {
	if err.HTTPStatus == 401 {
		return err.Code == jack.CodeReplayedNonce || err.Code == jack.CodeTimestampOutOfWindow
	}
	if err.HTTPStatus == 503 {
		return err.Code == "state_changed" || err.Code == "capacity_exhausted"
	}
	return false
}

func storageRejection(err *jack.Error) Result {
	if err.HTTPStatus == 401 && (err.Code == jack.CodeReplayedNonce || err.Code == jack.CodeTimestampOutOfWindow) {
		return rejection(401, err.Code, "request was not admitted")
	}
	if err.HTTPStatus == 503 {
		switch err.Code {
		case "durability_unavailable", "state_changed", "clock_unsafe", "capacity_exhausted":
			return rejection(503, err.Code, "durable admission is unavailable")
		}
	}
	return rejectionFrom(durableFailure())
}

func (v *Verifier) reserveDurable(auth jack.RequestAuth, signing string, caller RegistryEntry, known bool) (Result, int64) {
	state := v.cfg.State.(AdmissionStateStore)
	var result Result
	returned := false
	defer func() {
		if !returned {
			result.Done()
		}
	}()
	var finalNow int64
	var called atomic.Bool
	err := state.WithAdmission(auth.Kid, func(current RegistryEntry, currentKnown bool) error {
		if !called.CompareAndSwap(false, true) {
			return durableFailure()
		}
		if currentKnown != known || (known && !sameEntry(current, caller)) {
			return &jack.Error{HTTPStatus: 503, Code: "state_changed", Message: "verification state changed"}
		}
		var active atomic.Bool
		active.Store(true)
		defer active.Store(false)
		request := NonceAdmission{
			KID: auth.Kid, Nonce: auth.Nonce, Signature: auth.Sig, SigningBytes: signing,
			Timestamp: auth.TS, Window: v.cfg.Window, Now: v.cfg.Now,
			Validate: func(now int64) bool {
				return active.Load() && now >= 0 && now <= maxDurableTimestamp &&
					(!known || entryActive(current, now))
			},
		}
		if auth.TS < 0 || auth.TS > maxDurableTimestamp-request.Window {
			return &jack.Error{HTTPStatus: 401, Code: jack.CodeTimestampOutOfWindow, Message: "timestamp is outside the acceptance window"}
		}
		receipt, lease, storageErr := v.cfg.DurableNonces.Reserve(request)
		if storageErr != nil {
			if !definiteStorageRefusal(storageErr) {
				v.cfg.DurableNonces.Fence()
			}
			if lease != nil {
				lease.Release()
			}
			return storageErr
		}
		if lease == nil || !receiptMatches(receipt, request) {
			v.cfg.DurableNonces.Fence()
			if lease != nil {
				lease.Release()
			}
			return durableFailure()
		}
		result = Result{Kid: auth.Kid, NonceRecorded: true, RequestSig: auth.Sig, admission: &admissionLease{lease: lease}}
		finalNow = v.cfg.Now()
		if finalNow < receipt.HighWater || finalNow < 0 || finalNow > maxDurableTimestamp {
			v.cfg.DurableNonces.Fence()
			result.HTTPStatus, result.Code, result.Message = 503, "durability_unavailable", "durable admission is unavailable"
			return nil
		}
		if !lease.Valid() || !request.Validate(finalNow) {
			result.HTTPStatus, result.Code, result.Message = 503, "state_changed", "verification state changed"
			return nil
		}
		if d := finalNow-auth.TS; d > request.Window || -d > request.Window {
			result.HTTPStatus, result.Code, result.Message = 401, jack.CodeTimestampOutOfWindow, "timestamp is outside the acceptance window"
		}
		return nil
	})
	if err != nil {
		if result.admission != nil {
			v.cfg.DurableNonces.Fence()
			result.Done()
			return rejectionFrom(durableFailure()), 0
		}
		var storageErr *jack.Error
		if !errors.As(err, &storageErr) {
			storageErr = durableFailure()
		}
		return storageRejection(storageErr), 0
	}
	if !called.Load() || result.admission == nil {
		v.cfg.DurableNonces.Fence()
		return rejectionFrom(durableFailure()), 0
	}
	returned = true
	return result, finalNow
}
