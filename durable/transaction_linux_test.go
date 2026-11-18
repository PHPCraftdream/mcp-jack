//go:build linux

package durable

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
	bolt "go.etcd.io/bbolt"
)

func requireAdmissionCode(t *testing.T, err error, status int, code string) {
	t.Helper()
	var refusal *jack.Error
	if !errors.As(err, &refusal) || refusal.HTTPStatus != status || refusal.Code != code {
		t.Fatalf("wanted HTTP %d %s, got %v", status, code, err)
	}
}

// transaction.go: definite callback refusals stay distinct from unknown transactions.
func TestStoreUpdateGatesRejectionsAndMetadataAcknowledgment(t *testing.T) {
	t.Run("commit acknowledges", func(t *testing.T) {
		now := int64(100)
		owner, _, _ := testOwner(t, &now)
		before := owner.meta
		if rejection := owner.update(func(_ *bolt.Tx, next *metadata) error { next.HighWater++; return nil }); rejection != nil {
			t.Fatal(rejection)
		}
		if owner.meta.HighWater != before.HighWater+1 {
			t.Fatalf("metadata ACK = %+v", owner.meta)
		}
		if err := owner.db.View(func(tx *bolt.Tx) error {
			persisted, err := decodeMetadata(tx.Bucket([]byte("metadata")).Get(headerKey))
			if err != nil || persisted != owner.meta {
				return errors.New("in-memory metadata differs from committed header")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	for _, gate := range []string{"fenced", "closing", "closed"} {
		t.Run(gate, func(t *testing.T) {
			now := int64(100)
			owner, _, _ := testOwner(t, &now)
			switch gate {
			case "fenced":
				owner.fenced.Store(true)
			case "closing":
				owner.closing.Store(true)
			case "closed":
				owner.closed.Store(true)
			}
			called := false
			requireAdmissionCode(t, owner.update(func(*bolt.Tx, *metadata) error { called = true; return nil }), 503, "durability_unavailable")
			if called || !owner.fenced.Load() {
				t.Fatal("unavailable gate invoked callback or failed to fence")
			}
			if gate == "closed" {
				owner.closed.Store(false)
			}
			if err := owner.Close(); !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("fenced close: %v", err)
			}
		})
	}
	t.Run("definite application refusal", func(t *testing.T) {
		now := int64(100)
		owner, _, _ := testOwner(t, &now)
		before := owner.meta
		requireAdmissionCode(t, owner.update(func(*bolt.Tx, *metadata) error { return admissionError(401, jack.CodeReplayedNonce) }), 401, jack.CodeReplayedNonce)
		if owner.fenced.Load() || owner.meta != before {
			t.Fatal("definite refusal changed acknowledged state")
		}
	})
	for _, fixture := range []struct {
		name     string
		callback error
		seam     bool
		wantCode string
	}{
		{name: "unsafe callback", callback: admissionError(503, "clock_unsafe"), wantCode: "clock_unsafe"},
		{name: "unavailable callback", callback: unavailable(), wantCode: "durability_unavailable"},
		{name: "ordinary callback error", callback: errors.New("injected apply error"), wantCode: "durability_unavailable"},
		{name: "transaction error", seam: true, wantCode: "durability_unavailable"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			now := int64(100)
			owner, _, _ := testOwner(t, &now)
			before := owner.meta
			if fixture.seam {
				owner.transact = func(func(*bolt.Tx) error) error { return errors.New("injected unknown result") }
			}
			requireAdmissionCode(t, owner.update(func(_ *bolt.Tx, next *metadata) error { next.HighWater++; return fixture.callback }), 503, fixture.wantCode)
			if !owner.fenced.Load() || owner.meta != before {
				t.Fatal("unavailable result was not fenced or acknowledged")
			}
			if err := owner.Close(); !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("fenced close: %v", err)
			}
		})
	}
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed current metadata", true: "invalid current metadata"}[corrupt], func(t *testing.T) {
			now := int64(100)
			owner, _, _ := testOwner(t, &now)
			if err := owner.db.Update(func(tx *bolt.Tx) error {
				bucket := tx.Bucket([]byte("metadata"))
				if corrupt {
					return bucket.Put(headerKey, []byte("broken"))
				}
				current, err := decodeMetadata(bucket.Get(headerKey))
				if err != nil {
					return err
				}
				current.HighWater++
				return bucket.Put(headerKey, encodeMetadata(current))
			}); err != nil {
				t.Fatal(err)
			}
			called := false
			requireAdmissionCode(t, owner.update(func(*bolt.Tx, *metadata) error { called = true; return nil }), 503, "durability_unavailable")
			if called || !owner.fenced.Load() {
				t.Fatal("invalid current metadata reached callback or failed to fence")
			}
			if err := owner.Close(); !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("fenced close: %v", err)
			}
		})
	}
}

// transaction.go: a readonly Put error and post-commit file checks cannot acknowledge metadata.
func TestStoreUpdateRejectsPutAndInvalidFileStats(t *testing.T) {
	t.Run("readonly Put", func(t *testing.T) {
		now := int64(100)
		owner, _, _ := testOwner(t, &now)
		before := owner.meta
		owner.transact = func(apply func(*bolt.Tx) error) error { return owner.db.View(apply) }
		requireAdmissionCode(t, owner.update(func(_ *bolt.Tx, next *metadata) error { next.HighWater++; return nil }), 503, "durability_unavailable")
		if !owner.fenced.Load() || owner.meta != before {
			t.Fatal("readonly Put was acknowledged or did not fence")
		}
		if err := owner.Close(); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatalf("fenced close: %v", err)
		}
	})
	for _, fixture := range []struct {
		name  string
		size  int64
		close bool
	}{
		{name: "stat error", close: true},
		{name: "undersized file", size: 1},
		{name: "oversized file", size: maxFileBytes + pageBytes},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			now := int64(100)
			owner, _, _ := testOwner(t, &now)
			original := owner.file
			fake, err := os.CreateTemp(t.TempDir(), "stat-fixture-")
			if err != nil {
				t.Fatal(err)
			}
			defer fake.Close()
			if fixture.size != 0 {
				if err := fake.Truncate(fixture.size); err != nil {
					t.Fatal(err)
				}
			}
			if fixture.close {
				if err := fake.Close(); err != nil {
					t.Fatal(err)
				}
			}
			owner.file = fake
			before := owner.meta
			rejection := owner.update(func(_ *bolt.Tx, next *metadata) error { next.HighWater++; return nil })
			owner.file = original
			requireAdmissionCode(t, rejection, 503, "durability_unavailable")
			if !owner.fenced.Load() || owner.meta != before {
				t.Fatal("invalid post-commit file stat acknowledged metadata")
			}
			if err := owner.Close(); !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("fenced close: %v", err)
			}
		})
	}
}

// transaction.go: readRecord requires an exact valid row of the requested kind.
func TestReadRecordRequiresExactValidLiveEntry(t *testing.T) {
	now := int64(100)
	owner, _, _ := testOwner(t, &now)
	row := testRecord(t, owner.meta, liveRecord)
	encoded, err := encodeRecord(row, owner.meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("live")).Put(row.key[:], encoded) }); err != nil {
		t.Fatal(err)
	}
	if err := owner.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("live"))
		if _, err := readRecord(nil, row.key, owner.meta, liveRecord); !errors.Is(err, ErrInvalidStore) {
			return errors.New("nil bucket accepted")
		}
		if _, err := readRecord(bucket, row.key, owner.meta, intentRecord); !errors.Is(err, ErrInvalidStore) {
			return errors.New("record kind mismatch accepted")
		}
		found, err := readRecord(bucket, row.key, owner.meta, liveRecord)
		if err != nil || found == nil || *found != row {
			return errors.New("valid exact record did not round trip")
		}
		missing := row.key
		missing[47]++
		if found, err := readRecord(bucket, missing, owner.meta, liveRecord); err != nil || found != nil {
			return errors.New("missing exact key was not absent")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	other := row
	var nonce [16]byte
	nonce[15] = 1
	other.key[47] = 1
	other.receipt.Nonce = jack.EncodeBase64URL(nonce[:])
	signature, err := jack.DecodeBase64URLFixed(other.receipt.Signature, 64)
	if err != nil {
		t.Fatal(err)
	}
	requestHash, err := jack.DecodeBase64URLFixed(other.receipt.RequestHash, 32)
	if err != nil {
		t.Fatal(err)
	}
	other.receipt.IntentID = storageIntentID(owner.meta, other.key, signature, requestHash, other.receipt.OperationID)
	otherBytes, err := encodeRecord(other, owner.meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("live")).Put(row.key[:], otherBytes) }); err != nil {
		t.Fatal(err)
	}
	if err := owner.db.View(func(tx *bolt.Tx) error {
		if _, err := readRecord(tx.Bucket([]byte("live")), row.key, owner.meta, liveRecord); !errors.Is(err, ErrInvalidStore) {
			return errors.New("different embedded key accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := owner.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("live")).Put(row.key[:], []byte("bad")) }); err != nil {
		t.Fatal(err)
	}
	if err := owner.db.View(func(tx *bolt.Tx) error {
		if _, err := readRecord(tx.Bucket([]byte("live")), row.key, owner.meta, liveRecord); !errors.Is(err, ErrInvalidStore) {
			return errors.New("malformed record accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// transaction.go: replay stays denied through equality and refuses orphan intent/tombstone rows.
func TestReplayLookupBoundariesAndMalformedHistory(t *testing.T) {
	for _, fixture := range []struct {
		name string
		kind byte
		now  int64
		code string
	}{
		{name: "live equality", kind: liveRecord, now: 130, code: jack.CodeReplayedNonce},
		{name: "expired live", kind: liveRecord, now: 131},
		{name: "intent orphan", kind: intentRecord, now: 100, code: "durability_unavailable"},
		{name: "tombstone orphan", kind: tombstoneRecord, now: 100, code: "durability_unavailable"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			now := int64(100)
			owner, _, _ := testOwner(t, &now)
			row := testRecord(t, owner.meta, fixture.kind)
			encoded, err := encodeRecord(row, owner.meta)
			if err != nil {
				t.Fatal(err)
			}
			bucketName := map[byte]string{liveRecord: "live", intentRecord: "intent", tombstoneRecord: "tombstone"}[fixture.kind]
			if err := owner.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(bucketName)).Put(row.key[:], encoded) }); err != nil {
				t.Fatal(err)
			}
			err = owner.db.View(func(tx *bolt.Tx) error { return replayLookup(tx, owner.meta, row.key, fixture.now) })
			if fixture.code == "" {
				if err != nil {
					t.Fatalf("expired live reservation still refused: %v", err)
				}
				return
			}
			status := 503
			if fixture.code == jack.CodeReplayedNonce {
				status = 401
			}
			requireAdmissionCode(t, err, status, fixture.code)
		})
	}
	for _, fixture := range []struct {
		name   string
		bucket string
		kind   byte
	}{
		{name: "malformed live", bucket: "live", kind: liveRecord},
		{name: "malformed intent", bucket: "intent", kind: intentRecord},
		{name: "malformed tombstone", bucket: "tombstone", kind: tombstoneRecord},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			now := int64(100)
			owner, _, _ := testOwner(t, &now)
			row := testRecord(t, owner.meta, fixture.kind)
			if err := owner.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(fixture.bucket)).Put(row.key[:], []byte{1}) }); err != nil {
				t.Fatal(err)
			}
			err := owner.db.View(func(tx *bolt.Tx) error { return replayLookup(tx, owner.meta, row.key, 100) })
			if !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("malformed %s row: %v", fixture.name, err)
			}
		})
	}
}

// transaction.go: purge uses strict expiry and preserves the exact pair's coupled indexes.
func TestPurgeExpiredExactPairAndRetentionEquality(t *testing.T) {
	now := int64(100)
	owner, _, _ := testOwner(t, &now)
	rows := seedLiveHistory(t, owner, 3, func(index int) int64 {
		if index == 2 {
			return 101
		}
		return 100
	})
	rejection := owner.update(func(tx *bolt.Tx, m *metadata) error {
		if err := purgeExpired(tx, m, 131, rows[0].key); err != nil {
			return err
		}
		if m.HighWater != 131 || m.Live != 1 {
			return errors.New("exact pair or equality purge disposition changed")
		}
		for index, row := range rows {
			found, err := readRecord(tx.Bucket([]byte("live")), row.key, *m, liveRecord)
			if err != nil || ((found != nil) != (index == 2)) {
				return errors.New("wrong purge disposition")
			}
		}
		return validateRows(tx, *m)
	})
	if rejection != nil {
		t.Fatal(rejection)
	}
	equalityNow := int64(100)
	equalityOwner, _, _ := testOwner(t, &equalityNow)
	equality := seedLiveHistory(t, equalityOwner, 1, func(int) int64 { return 100 })[0]
	rejection = equalityOwner.update(func(tx *bolt.Tx, m *metadata) error {
		if err := purgeExpired(tx, m, 130, equality.key); err != nil {
			return err
		}
		if m.Live != 1 {
			return errors.New("expiry equality was deleted")
		}
		return validateRows(tx, *m)
	})
	if rejection != nil {
		t.Fatal(rejection)
	}
}

// transaction.go: purge validates expiry metadata before deleting live and coupled indexes.
func TestPurgeExpiredReadOnlyDeleteFailure(t *testing.T) {
	now := int64(100)
	owner, _, _ := testOwner(t, &now)
	row := seedLiveHistory(t, owner, 1, func(int) int64 { return 100 })[0]
	err := owner.db.View(func(tx *bolt.Tx) error {
		m := owner.meta
		return purgeExpired(tx, &m, 131, row.key)
	})
	if err == nil {
		t.Fatal("purge in readonly transaction deleted expired row")
	}
	if err := owner.db.View(func(tx *bolt.Tx) error {
		found, err := readRecord(tx.Bucket([]byte("live")), row.key, owner.meta, liveRecord)
		if err != nil || found == nil {
			return errors.New("readonly purge removed live row")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
}

// transaction.go: purge validates an exact expired row before consulting its index.
func TestPurgeExpiredRejectsMalformedExactRow(t *testing.T) {
	now := int64(100)
	owner, _, _ := testOwner(t, &now)
	row := testRecord(t, owner.meta, liveRecord)
	if err := owner.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("live")).Put(row.key[:], []byte{1}) }); err != nil {
		t.Fatal(err)
	}
	err := owner.db.Update(func(tx *bolt.Tx) error {
		m := owner.meta
		return purgeExpired(tx, &m, 131, row.key)
	})
	if !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("malformed exact row accepted: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
}

// transaction.go: malformed expiry metadata cannot partially commit deletion.
func TestPurgeExpiredRejectsRollbackAndMalformedIndexes(t *testing.T) {
	for _, fixture := range []string{"high water rollback", "short key", "nonempty value", "nested bucket", "missing exact index", "missing live pair", "expiry mismatch", "operation mismatch", "zero live count"} {
		t.Run(fixture, func(t *testing.T) {
			now := int64(100)
			owner, _, _ := testOwner(t, &now)
			if fixture == "high water rollback" {
				err := owner.db.Update(func(tx *bolt.Tx) error {
					m := owner.meta
					return purgeExpired(tx, &m, m.HighWater-1, [48]byte{})
				})
				if !errors.Is(err, ErrInvalidStore) {
					t.Fatalf("rollback purge: %v", err)
				}
				return
			}
			var row nonceRecord
			if fixture != "missing live pair" && fixture != "short key" {
				row = seedLiveHistory(t, owner, 1, func(int) int64 { return 100 })[0]
			}
			if err := owner.db.Update(func(tx *bolt.Tx) error {
				expiry := tx.Bucket([]byte("expiry"))
				switch fixture {
				case "short key":
					return expiry.Put([]byte{1}, []byte{})
				case "nonempty value":
					index := expiryKey(row)
					return expiry.Put(index[:], []byte{1})
				case "nested bucket":
					index := expiryKey(row)
					if err := expiry.Delete(index[:]); err != nil {
						return err
					}
					_, err := expiry.CreateBucket(index[:])
					return err
				case "missing exact index":
					index := expiryKey(row)
					return expiry.Delete(index[:])
				case "missing live pair":
					row = testRecord(t, owner.meta, liveRecord)
					index := expiryKey(row)
					return expiry.Put(index[:], []byte{})
				case "expiry mismatch":
					old := expiryKey(row)
					if err := expiry.Delete(old[:]); err != nil {
						return err
					}
					wrong := old
					binary.BigEndian.PutUint64(wrong[:8], uint64(129))
					return expiry.Put(wrong[:], []byte{})
				case "operation mismatch":
					var value [48]byte
					value[47] = 1
					return tx.Bucket([]byte("operation")).Put(row.receipt.OperationID[:], value[:])
				case "zero live count":
					return nil
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before := owner.meta
			err := owner.db.Update(func(tx *bolt.Tx) error {
				m := owner.meta
				if fixture == "zero live count" {
					m.Live = 0
				}
				return purgeExpired(tx, &m, 131, row.key)
			})
			if !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("malformed %s accepted: %v", fixture, err)
			}
			if owner.meta != before {
				t.Fatal("failed purge changed acknowledged metadata")
			}
			if err := owner.Close(); err != nil {
				t.Fatalf("fixture close: %v", err)
			}
		})
	}
}

func TestPurgeExpiredValidatesWholeIndexBeforeDeletion(t *testing.T) {
	now := int64(100)
	owner, _, _ := testOwner(t, &now)
	rows := seedLiveHistory(t, owner, 2, func(int) int64 { return 100 })
	badKey := []byte("not-an-expiry-key")
	if err := owner.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("expiry")).Put(badKey, []byte{}) }); err != nil {
		t.Fatal(err)
	}
	err := owner.db.Update(func(tx *bolt.Tx) error {
		m := owner.meta
		return purgeExpired(tx, &m, 131, rows[0].key)
	})
	if !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("malformed index accepted: %v", err)
	}
	if err := owner.db.View(func(tx *bolt.Tx) error {
		for _, row := range rows {
			found, err := readRecord(tx.Bucket([]byte("live")), row.key, owner.meta, liveRecord)
			if err != nil || found == nil {
				return errors.New("failed purge deleted live row")
			}
			index := expiryKey(row)
			if value := tx.Bucket([]byte("expiry")).Get(index[:]); value == nil || len(value) != 0 {
				return errors.New("failed purge deleted expiry index")
			}
			if !bytes.Equal(tx.Bucket([]byte("operation")).Get(row.receipt.OperationID[:]), row.key[:]) {
				return errors.New("failed purge changed operation index")
			}
		}
		if tx.Bucket([]byte("expiry")).Get(badKey) == nil {
			return errors.New("failed purge committed malformed-index removal")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := owner.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("expiry")).Delete(badKey) }); err != nil {
		t.Fatal(err)
	}
	if err := owner.db.View(func(tx *bolt.Tx) error { return validateRows(tx, owner.meta) }); err != nil {
		t.Fatal(err)
	}
}

// History is created in a single transaction; each record has a real signed request.
func seedLiveHistory(t *testing.T, owner *Store, count int, timestamp func(int) int64) []nonceRecord {
	t.Helper()
	seed := sha256.Sum256([]byte("mcp-jack public capacity history"))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)
	kid := jack.KeyID(public)
	rows := make([]nonceRecord, count)
	for index := range rows {
		var nonce, operation [16]byte
		binary.BigEndian.PutUint64(nonce[8:], uint64(index+1))
		binary.BigEndian.PutUint64(operation[8:], uint64(index+1))
		ts := timestamp(index)
		encodedNonce := jack.EncodeBase64URL(nonce[:])
		signing := jack.RequestSigningString("GET", "/mcp", "public-capacity-test", kid, ts, encodedNonce, nil)
		request := server.NonceAdmission{KID: kid, Nonce: encodedNonce, Signature: jack.EncodeBase64URL(ed25519.Sign(private, []byte(signing))), SigningBytes: signing, Timestamp: ts, Window: owner.meta.Window}
		intent, err := server.NonceIntentID(owner.meta.Deployment, request, operation)
		if err != nil {
			t.Fatal(err)
		}
		row := nonceRecord{kind: liveRecord, storeID: owner.meta.StoreID}
		digest := sha256.Sum256(public)
		copy(row.key[:32], digest[:])
		copy(row.key[32:], nonce[:])
		row.receipt = server.NonceReceipt{Version: formatVersion, DeploymentID: owner.meta.Deployment, StoreGeneration: owner.meta.Generation, OwnerGeneration: owner.meta.Owner, IntentID: intent, OperationID: operation, KID: kid, Nonce: encodedNonce, Signature: request.Signature, RequestHash: jack.BodyHash([]byte(signing)), Timestamp: ts, RetainUntil: ts + owner.meta.Window, HighWater: owner.meta.HighWater}
		rows[index] = row
	}
	if rejection := owner.update(func(tx *bolt.Tx, m *metadata) error {
		for _, row := range rows {
			encoded, err := encodeRecord(row, *m)
			if err != nil {
				return err
			}
			if err := tx.Bucket([]byte("live")).Put(row.key[:], encoded); err != nil {
				return err
			}
			index := expiryKey(row)
			if err := tx.Bucket([]byte("expiry")).Put(index[:], []byte{}); err != nil {
				return err
			}
			if err := tx.Bucket([]byte("operation")).Put(row.receipt.OperationID[:], row.key[:]); err != nil {
				return err
			}
			m.Live++
		}
		return validateRows(tx, *m)
	}); rejection != nil {
		t.Fatal(rejection)
	}
	return rows
}

func TestPurgeShares128BudgetWithExactPairAndPreservesEquality(t *testing.T) {
	now := int64(100)
	owner, _, _ := testOwner(t, &now)
	rows := seedLiveHistory(t, owner, 131, func(index int) int64 {
		if index == 130 {
			return 101
		}
		return 100
	})
	now = 131
	if rejection := owner.update(func(tx *bolt.Tx, m *metadata) error {
		if err := purgeExpired(tx, m, now, rows[129].key); err != nil {
			return err
		}
		if m.HighWater != now || m.Live != 3 {
			return errors.New("purge exceeded 128 or skipped adjacent expired rows")
		}
		for index, row := range rows {
			got, err := readRecord(tx.Bucket([]byte("live")), row.key, *m, liveRecord)
			if err != nil {
				return err
			}
			wantPresent := index == 127 || index == 128 || index == 130
			if (got != nil) != wantPresent {
				return errors.New("wrong purge disposition or equality expired")
			}
		}
		return validateRows(tx, *m)
	}); rejection != nil {
		t.Fatal(rejection)
	}
}

func TestLastCapacitySlotConvertsIntentWithoutDoubleCounting(t *testing.T) {
	now := int64(100)
	owner, _, _ := testOwner(t, &now)
	seedLiveHistory(t, owner, 4095, func(int) int64 { return 100 })
	state := server.NewMemoryState()
	verifier := actualVerifier(t, owner, state, &now)
	request := signedStorageRequest(t, state, 100, 8)
	original := owner.transact
	calls := 0
	owner.transact = func(apply func(*bolt.Tx) error) error {
		calls++
		err := original(apply)
		if calls == 1 && err == nil {
			if err := owner.db.View(func(tx *bolt.Tx) error {
				m, err := decodeMetadata(tx.Bucket([]byte("metadata")).Get(headerKey))
				if err != nil {
					return err
				}
				if m.Live != 4095 || m.Intents != 1 {
					return errors.New("intent did not reserve the final capacity slot")
				}
				return validateRows(tx, m)
			}); err != nil {
				t.Error(err)
			}
		}
		return err
	}
	result := verifier.Verify(request)
	result.Done()
	if !result.Accepted || !result.NonceRecorded || calls != 2 || owner.meta.Live != 4096 || owner.meta.Intents != 0 {
		t.Fatalf("last slot failed conversion: %+v calls=%d", result, calls)
	}
	before := owner.meta
	overflow := verifier.Verify(signedStorageRequest(t, state, 100, 9))
	overflow.Done()
	if overflow.Accepted || overflow.NonceRecorded || overflow.Code != "capacity_exhausted" || calls != 3 || owner.meta != before || owner.fenced.Load() {
		t.Fatalf("capacity refusal changed state: %+v calls=%d", overflow, calls)
	}
	if err := owner.db.View(func(tx *bolt.Tx) error { return validateRows(tx, owner.meta) }); err != nil {
		t.Fatal(err)
	}
}

func unknownFinalSnapshot(t *testing.T, committed bool) (string, Options, RecoverySnapshot, server.NonceReceipt) {
	t.Helper()
	now := int64(100)
	owner, path, opts := testOwner(t, &now)
	state := server.NewMemoryState()
	request := signedStorageRequest(t, state, 100, 12)
	original := owner.transact
	calls := 0
	injected := errors.New("public recovery fixture uncertainty")
	owner.transact = func(apply func(*bolt.Tx) error) error {
		calls++
		if calls != 2 {
			return original(apply)
		}
		if committed {
			if err := original(apply); err != nil {
				return err
			}
			return injected
		}
		return original(func(tx *bolt.Tx) error {
			if err := apply(tx); err != nil {
				return err
			}
			return injected
		})
	}
	result := actualVerifier(t, owner, state, &now).Verify(request)
	result.Done()
	if result.Accepted || result.NonceRecorded || calls != 2 || !owner.fenced.Load() {
		t.Fatalf("unknown fixture admitted or retried: %+v", result)
	}
	_ = owner.Close()
	opts.Now = func() int64 { panic("reconciliation must not sample clock") }
	snapshot, err := InspectRecovery(path, opts)
	if err != nil || !snapshot.Dirty || len(snapshot.Live)+len(snapshot.Intents) != 1 {
		t.Fatalf("unknown fixture lost persisted outcome: %+v %v", snapshot, err)
	}
	if committed {
		return path, opts, snapshot, snapshot.Live[0]
	}
	return path, opts, snapshot, snapshot.Intents[0]
}

func TestExactUnknownReconciliationCreatesTerminalTombstoneWithoutReopen(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "final-absent", true: "final-present"}[committed], func(t *testing.T) {
			path, opts, before, receipt := unknownFinalSnapshot(t, committed)
			if err := ReconcileUnknown(path, opts, before.Hash, receipt); err != nil {
				t.Fatal(err)
			}
			after, err := InspectRecovery(path, opts)
			if err != nil || !after.Dirty || after.Unsafe != before.Unsafe || after.HighWater != before.HighWater || after.StoreGeneration != before.StoreGeneration || after.OwnerGeneration != before.OwnerGeneration || after.StoreID != before.StoreID || after.Hash == before.Hash || len(after.Live) != 0 || len(after.Intents) != 0 || len(after.Tombstones) != 1 || after.Tombstones[0] != receipt {
				t.Fatalf("terminal reconciliation changed identity or cleared fence: %+v %v", after, err)
			}
			if err := ReconcileUnknown(path, opts, before.Hash, receipt); !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("stale snapshot was accepted: %v", err)
			}
			if err := ReconcileUnknown(path, opts, after.Hash, receipt); err != nil {
				t.Fatal("explicit exact terminal recheck was not idempotent:", err)
			}
			again, err := InspectRecovery(path, opts)
			if err != nil || again.Hash != after.Hash {
				t.Fatalf("terminal recheck rewrote logical history: %v", err)
			}
			opts.Now = func() int64 { return 2000 }
			if opened, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
				if opened != nil {
					opened.Fence()
					_ = opened.Close()
				}
				t.Fatalf("reconciliation or expiry authorized serving: %v", err)
			}
		})
	}
}

func TestReconciliationRejectsInexactReceiptAndAbsentOperationWithoutWrites(t *testing.T) {
	path, opts, snapshot, receipt := unknownFinalSnapshot(t, false)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*server.NonceReceipt){
		func(r *server.NonceReceipt) { r.OperationID[0] ^= 1 },
		func(r *server.NonceReceipt) { r.IntentID = "wrong" },
		func(r *server.NonceReceipt) { r.HighWater++ },
		func(r *server.NonceReceipt) { r.OwnerGeneration++ },
	} {
		wrong := receipt
		mutate(&wrong)
		if err := ReconcileUnknown(path, opts, snapshot.Hash, wrong); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatalf("inexact operation was reconciled: %v", err)
		}
	}
	// Canonical but missing pair; absence does not permit reset/reopen.
	missing := receipt
	missing.Nonce = "AAAAAAAAAAAAAAAAAAAAAA"
	if err := ReconcileUnknown(path, opts, snapshot.Hash, missing); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("absent operation cleared unknown: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("definite reconciliation rejection changed database bytes")
	}
}

func TestReconciliationRefusesCleanStore(t *testing.T) {
	now := int64(100)
	owner, path, opts := testOwner(t, &now)
	seedLiveHistory(t, owner, 1, func(int) int64 { return 100 })
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectRecovery(path, opts)
	if err != nil || snapshot.Dirty || len(snapshot.Live) != 1 {
		t.Fatalf("clean fixture: %+v %v", snapshot, err)
	}
	if err := ReconcileUnknown(path, opts, snapshot.Hash, snapshot.Live[0]); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("normal committed operation was marked unknown: %v", err)
	}
}

func TestReconciliationTombstoneCapacityNeverEvictsHistory(t *testing.T) {
	now := int64(100)
	owner, path, opts := testOwner(t, &now)
	seedLiveHistory(t, owner, 65, func(int) int64 { return 100 })
	owner.Fence()
	_ = owner.Close()
	snapshot, err := InspectRecovery(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	for count := 0; count < 64; count++ {
		if err := ReconcileUnknown(path, opts, snapshot.Hash, snapshot.Live[0]); err != nil {
			t.Fatal(err)
		}
		snapshot, err = InspectRecovery(path, opts)
		if err != nil || len(snapshot.Tombstones) != count+1 || len(snapshot.Live) != 64-count {
			t.Fatalf("capacity conversion lost history: %+v %v", snapshot, err)
		}
	}
	if err := ReconcileUnknown(path, opts, snapshot.Hash, snapshot.Live[0]); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("tombstone capacity exceeded: %v", err)
	}
	after, err := InspectRecovery(path, opts)
	if err != nil || after.Hash != snapshot.Hash || len(after.Tombstones) != 64 || len(after.Live) != 1 || !after.Dirty {
		t.Fatalf("capacity refusal evicted or changed history: %+v %v", after, err)
	}
}

func TestUnknownReconciliationCommitNeverRetriesOrClearsDirty(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "tombstone-absent", true: "tombstone-present"}[committed], func(t *testing.T) {
			path, opts, before, receipt := unknownFinalSnapshot(t, false)
			calls := 0
			injected := errors.New("public unknown reconciliation commit")
			err := reconcileUnknown(path, opts, before.Hash, receipt, func(db *bolt.DB, apply func(*bolt.Tx) error) error {
				calls++
				if committed {
					if err := db.Update(apply); err != nil {
						return err
					}
					return injected
				}
				return db.Update(func(tx *bolt.Tx) error {
					if err := apply(tx); err != nil {
						return err
					}
					return injected
				})
			})
			if !errors.Is(err, ErrUnavailable) || calls != 1 {
				t.Fatalf("unknown reconciliation retried or reported success: %v calls=%d", err, calls)
			}
			after, err := InspectRecovery(path, opts)
			if err != nil || !after.Dirty || (len(after.Tombstones) == 1) != committed || (len(after.Intents) == 1) == committed || len(after.Tombstones)+len(after.Intents) != 1 {
				t.Fatalf("unknown recovery outcome lost exact disposition: %+v %v", after, err)
			}
		})
	}
}
