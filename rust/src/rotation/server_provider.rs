use super::{
    create_record, decode_result, invalid, Binding, Checkpoint, ClockTuple, DecodedResult, Record,
    ResultCursor, RotationError, RotationServerStore, ServerSnapshot, SignerReference, TrustKey,
    GRACE_SECONDS, MAX_ORDINAL, MAX_RETAINED_KEYS, MAX_RESULT_BODY_BYTES,
    MAX_SIGNER_REFERENCE_BYTES, MAX_TIMESTAMP,
};
use crate::client::Signer;
use crate::ed25519::validate_public_key;
use crate::encoding::key_id;
use crate::server::response_keys::{
    FinalGate, Release, ResponseKeyAuthorization, ResponseKeyRequest, ResponseKeys, ResponseSigner,
};
use crate::server::verify::TOOL_SERVER_KEY;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

// Лимиты TS/Go reference (Go hardcoded 128/1024): аномальное число pending/retained handles отказывает.
const MAX_PENDING: usize = 128;
const MAX_RETIRED: usize = 1024;

fn unavailable() -> RotationError {
    invalid("rotation_state_unavailable")
}

/// Reset флага публикации на любом выходе, включая `?`; Go: `defer publication.Store(false)`.
/// Привязка к `&AtomicBool`, чтобы guard не владел флагом и жил ровно до конца announce.
struct PublicationReset<'a>(&'a AtomicBool);

impl Drop for PublicationReset<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Заранее настроенный handle подписанта: reference не заменяет проверку публичного ключа.
pub struct RotationServerKey {
    pub reference: String,
    pub signer: Arc<dyn Signer>,
}

/// Pinned identity подписанта: публичный ключ скопирован один раз и не меняется вместе с callback.
#[derive(Clone)]
pub struct PinnedRotationSigner {
    public: [u8; 32],
    signer: Arc<dyn Signer>,
}

impl AsRef<dyn Signer> for PinnedRotationSigner {
    fn as_ref(&self) -> &(dyn Signer + 'static) {
        self.signer.as_ref()
    }
}

impl ResponseSigner for PinnedRotationSigner {
    fn public_key(&self) -> [u8; 32] {
        self.public
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RotationError> {
        // Raw signature bytes: length/verify остаются HTTP-слою (Go responseSignature).
        self.signer.sign(message).map_err(|_| unavailable())
    }
}

/// Только после exact durable ACK; это не HTTP delivery.
pub struct RotationPublication {
    pub record: Record,
    pub revision: u64,
}

/// Связывает concrete server store с заранее настроенным inventory подписантов: выбор подписанта,
/// явная публикация одного next key и авторизация response signing. Inventory задаётся только
/// out-of-band; custody и lifecycle signer handles принадлежат caller. Signer callbacks должны
/// быть bounded и не reentrant; store lock никогда не держится во время callbacks.
pub struct RotationServerProvider<C: FnMut() -> Result<u64, RotationError> + Send + 'static> {
    store: Arc<Mutex<RotationServerStore<C>>>,
    keys: HashMap<(String, String), PinnedRotationSigner>,
    publishing: AtomicBool,
}

/// Копирует public identity ОДИН раз; kid считается от копии, поэтому поздние изменения
/// callback не могут подменить pinned identity. Rust String всегда валидный UTF-8, поэтому
/// utf8-проверки TS pin()/Go pinKey здесь не нужны.
fn pin(key: &RotationServerKey) -> Result<PinnedRotationSigner, RotationError> {
    let reference = key.reference.as_str();
    let public = key.signer.public_key();
    if reference.is_empty()
        || reference.len() > MAX_SIGNER_REFERENCE_BYTES
        || validate_public_key(&public).is_err()
    {
        return Err(unavailable());
    }
    Ok(PinnedRotationSigner {
        public,
        signer: Arc::clone(&key.signer),
    })
}

/// Pure выбор pinned подписанта без store и lock: требует все pending handles и текущий signer,
/// retired handles необязательны. Greatest eligible ordinal выигрывает неявно (позже index —
/// больше ordinal); fallback отсутствует. Snapshot уже полностью проверен; после fresh clock
/// sample остаётся только interval arithmetic.
fn select_pinned(
    keys: &HashMap<(String, String), PinnedRotationSigner>,
    snapshot: &ServerSnapshot,
    clock: &ClockTuple,
) -> Result<PinnedRotationSigner, RotationError> {
    let mut selected: Option<&PinnedRotationSigner> = None;
    let mut pending = 0usize;
    let mut retired = 0usize;
    for (index, key) in snapshot.public.keys.iter().enumerate() {
        let eligible = key.not_before <= clock.high_water
            && key.known_cutoff.is_none_or(|cutoff| clock.high_water < cutoff);
        let is_pending = key.not_before > clock.high_water;
        if is_pending {
            pending += 1;
        }
        if key.known_cutoff.is_some_and(|cutoff| cutoff <= clock.high_water) {
            retired += 1;
        }
        if pending > MAX_PENDING || retired > MAX_RETIRED {
            return Err(unavailable());
        }
        // Retired handles необязательны: они выпадают до lookup reference.
        if !eligible && !is_pending {
            continue;
        }
        // Validated snapshots гарантируют равные длины; defensive refuse на расхождение.
        let reference = snapshot
            .signer_references
            .get(index)
            .ok_or_else(unavailable)?;
        let signer = keys
            .get(&(reference.reference.clone(), key.kid.clone()))
            .ok_or_else(unavailable)?;
        // Identity theft guard: pinned public обязан совпадать с committed key.
        if signer.public != key.public_key {
            return Err(unavailable());
        }
        if eligible {
            selected = Some(signer);
        }
    }
    selected.cloned().ok_or_else(unavailable)
}

fn snapshot_signer_kid(snapshot: &ServerSnapshot, public: &[u8; 32]) -> String {
    snapshot
        .public
        .keys
        .iter()
        .find(|key| &key.public_key == public)
        .map(|key| key.kid.clone())
        .unwrap_or_default()
}

/// Go matchesNativeResponse: страница обязана точно продолжать committed ring, иначе отказ.
fn matches_page(
    page: &DecodedResult,
    snapshot: &ServerSnapshot,
    signer: &PinnedRotationSigner,
) -> bool {
    if page.current_public_key != signer.public
        || page.current_kid != snapshot_signer_kid(snapshot, &signer.public)
        || page.head_ordinal != snapshot.public.head.ordinal
        || page.head_hash != snapshot.public.head.hash
    {
        return false;
    }
    if page.records.is_empty() {
        return page.complete;
    }
    // Первый совпавший start фиксируется как в Go; последующие не пробуются.
    let Some(start) = snapshot
        .public
        .records
        .iter()
        .position(|wire| wire == &page.records[0])
    else {
        return false;
    };
    let end = start + page.records.len();
    if end > snapshot.public.records.len()
        || page.complete != (end == snapshot.public.records.len())
    {
        return false;
    }
    snapshot.public.records[start..end] == page.records[..]
}

// Map-only schema: plain derive терпит unknown members как Go partial unmarshal;
// missing id ломает parse — тот же исход, что nil-id путь Go.
#[derive(Deserialize)]
struct EnvelopeId {
    id: Box<RawValue>,
}

impl<C: FnMut() -> Result<u64, RotationError> + Send + 'static> RotationServerProvider<C> {
    /// Не создаёт state и не разрешает publication; отказывает, если ring не готов к serving.
    /// Input inventory копируется: последующие caller mutations не меняют pinned identity.
    pub fn new(
        store: Arc<Mutex<RotationServerStore<C>>>,
        keys: Vec<RotationServerKey>,
    ) -> Result<Self, RotationError> {
        if keys.is_empty() || keys.len() > MAX_RETAINED_KEYS {
            return Err(unavailable());
        }
        let mut pinned: HashMap<(String, String), PinnedRotationSigner> =
            HashMap::with_capacity(keys.len());
        for key in keys {
            let signer = pin(&key)?;
            // Rust-эквивалент TS identity(reference, kid): составной ключ вместо JSON-строки.
            let identity = (key.reference.clone(), key_id(&signer.public));
            if pinned.contains_key(&identity) {
                return Err(unavailable());
            }
            pinned.insert(identity, signer);
        }
        let provider = Self {
            store,
            keys: pinned,
            publishing: AtomicBool::new(false),
        };
        provider.ready()?;
        Ok(provider)
    }

    /// Readiness: committed ring, свежий ClockGuard и все pending/current handles доступны.
    pub fn ready(&self) -> Result<(), RotationError> {
        let mut store = self.lock_store();
        let _lease = store.acquire_serving_lease().map_err(|_| unavailable())?;
        let (snapshot, _) = store.snapshot()?;
        let clock = store.check_snapshot_clock(&snapshot)?;
        let _ = self.select_signer(&snapshot, &clock)?;
        Ok(())
    }

    /// Требует handles всех pending keys и текущего signer; retired handles необязательны.
    /// Никакого fallback: greatest eligible ordinal или отказ. Чистая функция без store access.
    pub fn select_signer(
        &self,
        snapshot: &ServerSnapshot,
        clock: &ClockTuple,
    ) -> Result<PinnedRotationSigner, RotationError> {
        select_pinned(&self.keys, snapshot, clock)
    }

    /// Одна explicit authorization для заранее настроенного next handle. P фиксируется одним
    /// fresh sample; отказ, конфликт или unknown не повторяются автоматически.
    pub fn announce(
        &self,
        reference: &str,
        kid: &str,
    ) -> Result<RotationPublication, RotationError> {
        // Reentrancy gate: вложенная публикация из signer callback отказывает сразу.
        if self
            .publishing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(unavailable());
        }
        let _reset = PublicationReset(&self.publishing);
        // Unknown inventory entry отказывает до store и до первого clock sample.
        let next = self
            .keys
            .get(&(reference.to_owned(), kid.to_owned()))
            .ok_or_else(unavailable)?;
        let mut store = self.lock_store();
        let _lease = store.acquire_serving_lease().map_err(|_| unavailable())?;
        let (snapshot, _) = store.snapshot()?;
        if snapshot.public.head.ordinal == MAX_ORDINAL
            || snapshot.public.revision == MAX_ORDINAL
            || snapshot.public.keys.len() >= MAX_RETAINED_KEYS
        {
            return Err(unavailable());
        }
        if snapshot
            .public
            .keys
            .iter()
            .any(|key| key.kid == kid || key.public_key == next.public)
        {
            return Err(unavailable());
        }
        let last = snapshot.public.keys.last().ok_or_else(unavailable)?;
        let tail = snapshot.signer_references.last().ok_or_else(unavailable)?;
        let old = self
            .keys
            .get(&(tail.reference.clone(), last.kid.clone()))
            .ok_or_else(unavailable)?;
        if old.public != last.public_key {
            return Err(unavailable());
        }
        // Совпадающий checkpoint берётся как есть; иначе previous выводится из последнего key.
        let previous = if last.ordinal == snapshot.public.checkpoint.ordinal {
            snapshot.public.checkpoint.clone()
        } else {
            Checkpoint {
                ordinal: last.ordinal,
                hash: snapshot.public.head.hash.clone(),
                kid: last.kid.clone(),
                public_key: last.public_key,
                // Go вычитает явно; validation делает вычитание точным — checked против corrupt store.
                published_at: last
                    .not_before
                    .checked_sub(GRACE_SECONDS)
                    .ok_or_else(unavailable)?,
            }
        };
        let clock = store.check_snapshot_clock(&snapshot)?;
        // Signer callbacks идут БЕЗ store lock: hook может сам двигать committed clock.
        drop(store);
        if clock.high_water > MAX_TIMESTAMP - GRACE_SECONDS {
            return Err(unavailable());
        }
        self.select_signer(&snapshot, &clock)?;
        if snapshot
            .public
            .keys
            .iter()
            .filter(|key| key.not_before > clock.high_water)
            .count()
            >= MAX_PENDING
        {
            return Err(unavailable());
        }
        // Любая ошибка CreateRecord мапится в unavailable; Go createPublication делает recover.
        // Паники callback сознательно не ловятся (crate-wide policy, в отличие от Go recover).
        let record = create_record(
            Binding {
                endpoint: &snapshot.public.binding.endpoint,
                aud: &snapshot.public.binding.aud,
            },
            &previous,
            old.as_ref(),
            next.as_ref(),
            clock.high_water,
        )
        .map_err(|_| unavailable())?;
        let mut public = snapshot.public.clone();
        let mut signer_references = snapshot.signer_references.clone();
        public.records.push(record.wire.clone());
        if let Some(retained) = public.keys.last_mut() {
            retained.known_cutoff = Some(record.activates_at);
        }
        public.keys.push(TrustKey {
            ordinal: record.ordinal,
            kid: record.new_kid.clone(),
            public_key: record.public_key,
            not_before: record.activates_at,
            known_cutoff: None,
        });
        public.head = ResultCursor {
            ordinal: record.ordinal,
            hash: record.hash.clone(),
        };
        // MAX check выше гарантирует точность инкремента.
        public.revision += 1;
        public.clock = clock.clone();
        signer_references.push(SignerReference {
            kid: kid.to_owned(),
            reference: reference.to_owned(),
        });
        let desired = ServerSnapshot {
            format_version: snapshot.format_version,
            public,
            signer_references,
        };
        let mut store = self.lock_store();
        // Raw store error: rotation_state_changed обязан пройти дословно и не fence'ит owner.
        store.compare_and_swap(&snapshot, &desired, &clock)?;
        Ok(RotationPublication {
            record,
            revision: desired.public.revision,
        })
    }

    /// Poisoned lock не паникует: fail closed через собственное состояние store.
    fn lock_store(&self) -> MutexGuard<'_, RotationServerStore<C>> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Полный envelope parse до signing-time clock; page нет для не-key authority ответов.
    fn response_page(
        &self,
        input: &ResponseKeyRequest,
    ) -> Result<Option<DecodedResult>, RotationError> {
        if input.tool != TOOL_SERVER_KEY || input.status != 200 {
            return Ok(None);
        }
        if input.body.len() > MAX_RESULT_BODY_BYTES {
            return Err(unavailable());
        }
        let envelope: EnvelopeId = serde_json::from_slice(input.body).map_err(|_| unavailable())?;
        decode_result(input.body, envelope.id.get().as_bytes())
            .map(Some)
            .map_err(|_| unavailable())
    }
}

impl<C: FnMut() -> Result<u64, RotationError> + Send + 'static> ResponseKeys
    for RotationServerProvider<C>
{
    /// Не доверяет body/tool при выборе identity и не делает fallback. Final однократен
    /// (Box<dyn FnOnce> потребляется вызовом — Go finalized CAS не нужен); Release обязателен
    /// после physical write, также при любой ошибке.
    fn authorize_response(
        &self,
        input: &ResponseKeyRequest,
    ) -> Result<ResponseKeyAuthorization, RotationError> {
        let page = self.response_page(input)?;
        let mut store = self.lock_store();
        let lease = store.acquire_serving_lease().map_err(|_| unavailable())?;
        // В отличие от announce, здесь ошибки store санитизируются в unavailable (Go parity).
        let (snapshot, _) = store.snapshot().map_err(|_| unavailable())?;
        let clock = store
            .check_snapshot_clock(&snapshot)
            .map_err(|_| unavailable())?;
        let signer = self
            .select_signer(&snapshot, &clock)
            .map_err(|_| unavailable())?;
        if let Some(page) = &page {
            if !matches_page(page, &snapshot, &signer) {
                return Err(unavailable());
            }
        }
        drop(store);
        let released = Arc::new(AtomicBool::new(false));
        let release_flag = Arc::clone(&released);
        let release: Release = Box::new(move || {
            // CAS повторяет Go: release логически однократен; lease в box падает и при drop без вызова.
            if release_flag
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                drop(lease);
            }
        });
        let signer_public = signer.public;
        let high_water = clock.high_water;
        let window = snapshot.public.window;
        // select_signer читает только pinned inventory: копия эквивалентна Go capture provider.
        let keys = self.keys.clone();
        let gate_store = Arc::clone(&self.store);
        let gate_released = Arc::clone(&released);
        let final_gate: FinalGate = Box::new(move || {
            if gate_released.load(Ordering::SeqCst) {
                return Err(unavailable());
            }
            let mut store = gate_store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let fresh = store
                .check_snapshot_clock(&snapshot)
                .map_err(|_| unavailable())?;
            // Свежесть окна строго вверх и не дальше window; вычитание защищено первой веткой.
            if fresh.high_water < high_water || fresh.high_water - high_water > window {
                return Err(unavailable());
            }
            let current = select_pinned(&keys, &snapshot, &fresh).map_err(|_| unavailable())?;
            if current.public != signer_public || gate_released.load(Ordering::SeqCst) {
                return Err(unavailable());
            }
            Ok(())
        });
        Ok(ResponseKeyAuthorization {
            signer: Arc::new(signer),
            timestamp: high_water,
            final_gate,
            release,
        })
    }
}
