package subscription

import "time"

// The default and finite bounds for TTL grants, in milliseconds.
const (
	DefaultTTLMs int64 = 3600000
	MinTTLMs     int64 = 60000
	MaxTTLMs     int64 = 86400000
)

// TTLValue represents an absent ttlMs, JSON null, or an integer. Callers
// must reject non-integral JSON values before putting a number in MS.
type TTLValue struct {
	Present bool
	Null    bool
	MS      int64
}

// Grant is the granted lifetime and its UTC refresh deadline. Both are nil
// for a subscription without expiry.
type Grant struct {
	GrantMS       *int64
	RefreshBefore *string
}

// TTLGrant computes the R8.5 grant given now in Unix seconds.
func TTLGrant(ttl TTLValue, now int64) (Grant, *KeyError) {
	grant := DefaultTTLMs
	if ttl.Present {
		if ttl.Null {
			return Grant{}, nil
		}
		if ttl.MS < 0 {
			return Grant{}, invalidArguments("ttl")
		}
		grant = min(max(ttl.MS, MinTTLMs), MaxTTLMs)
	}
	deadline := time.Unix(now+grant/1000, 0).UTC().Format("2006-01-02T15:04:05Z")
	return Grant{GrantMS: &grant, RefreshBefore: &deadline}, nil
}

// ActiveSecret is a signing key and whether it is the current key.
type ActiveSecret struct {
	Key     []byte
	Current bool
}

// ActiveSecrets returns current first, followed by previous only before the
// exclusive grace deadline. The returned keys alias the supplied slices.
func ActiveSecrets(current, previous []byte, hasPrevious bool, graceEndsAt, now int64) []ActiveSecret {
	active := []ActiveSecret{{Key: current, Current: true}}
	if hasPrevious && now < graceEndsAt {
		active = append(active, ActiveSecret{Key: previous})
	}
	return active
}
