//go:build linux

package durable

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
	bolt "go.etcd.io/bbolt"
)

// История создаётся одной транзакцией; каждая запись имеет настоящий signed request.
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
