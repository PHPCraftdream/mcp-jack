use super::private_file::FileOwner;
use super::server_store_format::{
    compatible_server, encode, unpack_server, RotationServerStoreOptions, ServerLoaded,
    SERVER_DOMAIN,
};
use super::store_format::{clock_bytes, read_clock, Bundle, RotationStoreOptions};
use super::{
    invalid, validate_server_publication, ClockTuple, RotationError, ServerSnapshot, MAX_ORDINAL,
    MAX_TIMESTAMP,
};
use crate::encoding::{body_hash, encode_b64url};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Удерживает dirty serving epoch до физического завершения response write; drop освобождает.
#[must_use = "a dropped lease no longer holds the dirty serving epoch"]
pub struct ServingLease {
    counter: Arc<AtomicUsize>,
}

impl Drop for ServingLease {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Private Linux server ring store: exclusive owner, независимый monotone ClockGuard, exact
/// whole-ring CAS одной fixed-P публикации. Callback и синхронный I/O должны завершаться bounded.
/// Не выбирает signer, не авторизует ответы и не восстанавливает dirty/unknown state; Drop
/// сохраняет dirty epoch/marker, только explicit close подтверждает clean state.
pub struct RotationServerStore<C: FnMut() -> Result<u64, RotationError>> {
    file: FileOwner,
    options: RotationStoreOptions,
    profile: String,
    store_id: String,
    owner: u64,
    now: C,
    busy: bool,
    fenced: bool,
    closing: bool,
    closed: bool,
    leases: Arc<AtomicUsize>,
}

impl<C: FnMut() -> Result<u64, RotationError>> RotationServerStore<C> {
    /// Explicit unused creation, не recovery или перезапись существующего состояния.
    pub fn initialize_unused(
        path: &Path,
        options: RotationServerStoreOptions,
        mut now: C,
    ) -> Result<(), RotationError> {
        let mut anchor = options.anchor()?;
        let base = options.base();
        let profile = body_hash(encode(&base, &anchor)?.as_bytes());
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| invalid("rotation_state_unavailable"))?;
        if id.iter().all(|byte| *byte == 0) {
            return Err(invalid("rotation_state_unavailable"));
        }
        let mut bundle = Bundle::sealed(
            SERVER_DOMAIN,
            encode_b64url(&id),
            profile,
            clock_bytes(&anchor.public.clock)?,
            encode(&base, &anchor)?,
        );
        let first = bundle.pack()?;
        let mut file = FileOwner::create_unused(path, &first)?;
        // Dirty state и marker подтверждены до первого callback.
        let result = (|| {
            let sampled = now().map_err(|_| invalid("rotation_state_unknown"))?;
            if sampled > MAX_TIMESTAMP {
                return Err(invalid("rotation_state_unknown"));
            }
            anchor.public.clock.high_water = sampled;
            anchor.public.clock.revision = 1;
            bundle.clock = clock_bytes(&anchor.public.clock)?;
            bundle.snapshot = encode(&base, &anchor)?;
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
    pub fn open(
        path: &Path,
        options: RotationServerStoreOptions,
        now: C,
    ) -> Result<Self, RotationError> {
        let base = options.base();
        let profile = body_hash(encode(&base, &options.anchor()?)?.as_bytes());
        let mut file = FileOwner::open(path)?;
        let mut mutation = false;
        let prepared = (|| {
            let mut state = unpack_server(file.read()?, &base, &profile)?;
            compatible_server(&state)?;
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
            options: base,
            profile,
            store_id,
            owner,
            now,
            busy: false,
            fenced: false,
            closing: false,
            closed: false,
            leases: Arc::new(AtomicUsize::new(0)),
        };
        store.advance_and_check()?;
        Ok(store)
    }

    fn begin(&mut self, code: &'static str) -> Result<(), RotationError> {
        if self.closed || self.closing || self.fenced {
            return Err(invalid(code));
        }
        if self.busy {
            self.fence();
            return Err(invalid(code));
        }
        self.busy = true;
        Ok(())
    }

    fn load(&mut self) -> Result<ServerLoaded, RotationError> {
        let state = unpack_server(self.file.read()?, &self.options, &self.profile)?;
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

    /// Committed read без нового time sample.
    pub fn snapshot(&mut self) -> Result<(ServerSnapshot, ClockTuple), RotationError> {
        self.begin("rotation_state_unavailable")?;
        let result = (|| {
            let state = self.load()?;
            compatible_server(&state)?;
            Ok((state.snapshot, state.clock))
        })();
        self.busy = false;
        if result.is_err() {
            self.fence();
        }
        result
    }

    /// Единственная операция, меняющая authoritative H/revision/unsafe.
    pub fn advance_and_check(&mut self) -> Result<ClockTuple, RotationError> {
        self.advance(None)
    }

    /// Exact ring плюс свежий server ClockGuard.
    pub fn check_snapshot_clock(
        &mut self,
        expected: &ServerSnapshot,
    ) -> Result<ClockTuple, RotationError> {
        let bytes = encode(&self.options, expected)?;
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

    /// Exact ring/current-guard CAS одной fixed-P публикации; logical clock bytes не меняются.
    pub fn compare_and_swap(
        &mut self,
        expected: &ServerSnapshot,
        desired: &ServerSnapshot,
        captured: &ClockTuple,
    ) -> Result<(), RotationError> {
        let previous = encode(&self.options, expected)?;
        let next = encode(&self.options, desired)?;
        let captured_bytes = clock_bytes(captured)?;
        read_clock(&captured_bytes, &self.options)?;
        if clock_bytes(&desired.public.clock)? != captured_bytes {
            return Err(invalid("rotation_state_changed"));
        }
        validate_server_publication(
            expected,
            desired,
            self.options.binding(),
            self.options.window,
            &self.options.checkpoint,
        )?;
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

    /// Новые операции и final gates после closing отказывают; lease держит dirty epoch.
    pub fn acquire_serving_lease(&mut self) -> Result<ServingLease, RotationError> {
        if self.closed || self.closing || self.fenced {
            return Err(invalid("rotation_state_unavailable"));
        }
        self.leases.fetch_add(1, Ordering::SeqCst);
        Ok(ServingLease {
            counter: Arc::clone(&self.leases),
        })
    }

    pub fn fence(&mut self) {
        self.fenced = true;
        self.file.fence();
    }

    /// Пока есть serving leases, close() отказывает без fence: caller освобождает leases и
    /// повторяет вызов. Caller обязан отдельно завершить network/final gates; Drop не заменяет close.
    pub fn close(&mut self) -> Result<(), RotationError> {
        if self.closed {
            return Ok(());
        }
        if self.fenced {
            return Err(invalid("rotation_state_unavailable"));
        }
        if self.busy {
            self.fence();
            return Err(invalid("rotation_state_unavailable"));
        }
        self.closing = true;
        if self.leases.load(Ordering::SeqCst) > 0 {
            return Err(invalid("rotation_state_unavailable"));
        }
        self.busy = true;
        let result = (|| {
            let mut state = self.load()?;
            compatible_server(&state)?;
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
