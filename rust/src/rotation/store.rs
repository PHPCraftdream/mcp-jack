use super::private_file::FileOwner;
use super::store_format::{
    clock_bytes, compatible, read_clock, unpack, Bundle, Loaded, RotationStoreOptions,
};
use super::{
    invalid, trust_clock_compatible, ClockTuple, RotationError, TrustSnapshot, MAX_ORDINAL,
    MAX_TIMESTAMP,
};
use crate::encoding::{body_hash, encode_b64url};
use std::path::Path;

/// Private Linux profile; callback и синхронный I/O должны завершаться bounded.
/// Drop сохраняет dirty epoch/marker; только explicit close подтверждает clean state.
pub struct RotationTrustStore<C: FnMut() -> Result<u64, RotationError>> {
    file: FileOwner,
    options: RotationStoreOptions,
    profile: String,
    store_id: String,
    owner: u64,
    now: C,
    busy: bool,
    fenced: bool,
    closed: bool,
}

impl<C: FnMut() -> Result<u64, RotationError>> RotationTrustStore<C> {
    /// Explicit unused creation, не recovery или перезапись существующего состояния.
    pub fn initialize_unused(
        path: &Path,
        options: RotationStoreOptions,
        mut now: C,
    ) -> Result<(), RotationError> {
        let mut anchor = options.anchor()?;
        let profile = body_hash(options.encode(&anchor)?.as_bytes());
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| invalid("rotation_state_unavailable"))?;
        if id.iter().all(|byte| *byte == 0) {
            return Err(invalid("rotation_state_unavailable"));
        }
        let mut bundle = Bundle::new(encode_b64url(&id), profile, &anchor, &options)?;
        let first = bundle.pack()?;
        let mut file = FileOwner::create_unused(path, &first)?;
        // Dirty state и marker подтверждены до первого callback.
        let result = (|| {
            let sampled = now().map_err(|_| invalid("rotation_state_unknown"))?;
            if sampled > MAX_TIMESTAMP {
                return Err(invalid("rotation_state_unknown"));
            }
            anchor.clock.high_water = sampled;
            anchor.clock.revision = 1;
            bundle.clock = clock_bytes(&anchor.clock)?;
            bundle.snapshot = options.encode(&anchor)?;
            bundle.dirty = false;
            file.replace(&first, &bundle.pack()?)?;
            file.close()
        })();
        if result.is_err() {
            file.fence();
            return Err(invalid("rotation_state_unknown"));
        }
        Ok(())
    }

    /// Noncreating startup; dirty/unsafe/uncertain artifacts не исправляются автоматически.
    pub fn open(path: &Path, options: RotationStoreOptions, now: C) -> Result<Self, RotationError> {
        let anchor = options.anchor()?;
        let profile = body_hash(options.encode(&anchor)?.as_bytes());
        let mut file = FileOwner::open(path)?;
        let mut mutation = false;
        let prepared = (|| {
            let mut state = unpack(file.read()?, &options, &profile)?;
            compatible(&state)?;
            if state.bundle.dirty || state.bundle.fenced || state.bundle.owner.0 == MAX_ORDINAL {
                return Err(invalid("rotation_state_unavailable"));
            }
            state.bundle.owner.0 += 1;
            state.bundle.dirty = true;
            mutation = true;
            file.replace(&state.bytes, &state.bundle.pack()?)?;
            Ok((state.bundle.store_id, state.bundle.owner.0))
        })();
        let (store_id, owner) = match prepared {
            Ok(value) => value,
            Err(error) => {
                if mutation {
                    file.fence();
                }
                let _ = file.close();
                return Err(error);
            }
        };
        let mut store = Self {
            file,
            options,
            profile,
            store_id,
            owner,
            now,
            busy: false,
            fenced: false,
            closed: false,
        };
        store.advance_and_check()?;
        Ok(store)
    }

    fn begin(&mut self, code: &'static str) -> Result<(), RotationError> {
        if self.closed || self.fenced {
            return Err(invalid(code));
        }
        if self.busy {
            self.fence();
            return Err(invalid(code));
        }
        self.busy = true;
        Ok(())
    }

    fn load(&mut self) -> Result<Loaded, RotationError> {
        let state = unpack(self.file.read()?, &self.options, &self.profile)?;
        if state.bundle.store_id != self.store_id
            || state.bundle.owner.0 != self.owner
            || !state.bundle.dirty
            || state.bundle.fenced
        {
            return Err(invalid("rotation_state_unavailable"));
        }
        Ok(state)
    }

    /// Preliminary sample, не durable ClockGuard authority.
    pub fn raw_clock(&mut self) -> Result<u64, RotationError> {
        self.begin("rotation_clock_unavailable")?;
        let result = (self.now)();
        self.busy = false;
        match result {
            Ok(now) => Ok(now),
            Err(_) => {
                self.fence();
                Err(invalid("rotation_clock_unavailable"))
            }
        }
    }

    /// Committed read без нового time sample или trust ACK.
    pub fn snapshot(&mut self) -> Result<(TrustSnapshot, ClockTuple), RotationError> {
        self.begin("rotation_state_unavailable")?;
        let result = (|| {
            let state = self.load()?;
            compatible(&state)?;
            Ok((state.snapshot, state.clock))
        })();
        self.busy = false;
        if result.is_err() {
            self.fence();
        }
        result
    }

    pub fn advance_and_check(&mut self) -> Result<ClockTuple, RotationError> {
        self.advance(None)
    }

    pub fn check_snapshot_clock(
        &mut self,
        expected: &TrustSnapshot,
    ) -> Result<ClockTuple, RotationError> {
        let bytes = self.options.encode(expected)?;
        self.advance(Some(bytes))
    }

    fn advance(&mut self, expected: Option<String>) -> Result<ClockTuple, RotationError> {
        self.begin("rotation_clock_unavailable")?;
        let result = (|| {
            let mut state = self.load()?;
            let mut clock = state.clock;
            if !clock.unsafe_clock {
                let now = (self.now)().map_err(|_| invalid("rotation_clock_unavailable"))?;
                let unsafe_clock = now > MAX_TIMESTAMP || now < clock.high_water;
                if unsafe_clock || now != clock.high_water {
                    if clock.revision == MAX_ORDINAL {
                        return Err(invalid("rotation_clock_unavailable"));
                    }
                    if !unsafe_clock {
                        clock.high_water = now;
                    }
                    clock.revision += 1;
                    clock.unsafe_clock = unsafe_clock;
                    state.bundle.clock = clock_bytes(&clock)?;
                    self.file.replace(&state.bytes, &state.bundle.pack()?)?;
                }
            }
            if clock.unsafe_clock {
                return Err(invalid("rotation_clock_unsafe"));
            }
            if expected.is_some_and(|bytes| bytes != state.bundle.snapshot) {
                return Err(invalid("rotation_state_changed"));
            }
            Ok(clock)
        })();
        self.busy = false;
        match result {
            Err(error)
                if error.code != "rotation_clock_unsafe"
                    && error.code != "rotation_state_changed" =>
            {
                self.fence();
                Err(invalid("rotation_clock_unavailable"))
            }
            other => other,
        }
    }

    /// Exact whole-snapshot/current-guard CAS; logical clock bytes не меняются.
    pub fn compare_and_swap(
        &mut self,
        expected: &TrustSnapshot,
        desired: &TrustSnapshot,
        captured: &ClockTuple,
    ) -> Result<(), RotationError> {
        let previous = self.options.encode(expected)?;
        let next = self.options.encode(desired)?;
        let captured_bytes = clock_bytes(captured)?;
        let captured = read_clock(&captured_bytes, &self.options)?;
        if expected.revision == MAX_ORDINAL
            || desired.revision != expected.revision + 1
            || expected.fenced
            || desired.fenced
            || !trust_clock_compatible(expected, &captured)
            || clock_bytes(&desired.clock)? != captured_bytes
            || desired.records.len() <= expected.records.len()
            || !desired.records.starts_with(&expected.records)
        {
            return Err(invalid("rotation_state_changed"));
        }
        self.begin("rotation_state_unavailable")?;
        let result = (|| {
            let mut state = self.load()?;
            if state.clock.unsafe_clock
                || state.bundle.snapshot != previous
                || state.bundle.clock != captured_bytes
            {
                return Err(invalid("rotation_state_changed"));
            }
            state.bundle.snapshot = next;
            self.file.replace(&state.bytes, &state.bundle.pack()?)
        })();
        self.busy = false;
        match result {
            Err(error) if error.code != "rotation_state_changed" => {
                self.fence();
                Err(invalid("rotation_state_unknown"))
            }
            other => other,
        }
    }

    pub fn fence(&mut self) {
        self.fenced = true;
        self.file.fence();
    }

    /// Caller обязан отдельно завершить network/final gates; Drop не заменяет close.
    pub fn close(&mut self) -> Result<(), RotationError> {
        if self.closed {
            return Ok(());
        }
        self.begin("rotation_state_unavailable")?;
        let result = (|| {
            let mut state = self.load()?;
            compatible(&state)?;
            state.bundle.dirty = false;
            self.file.replace(&state.bytes, &state.bundle.pack()?)?;
            self.file.close()?;
            self.closed = true;
            Ok(())
        })();
        self.busy = false;
        if result.is_err() {
            self.fence();
        }
        result
    }
}
