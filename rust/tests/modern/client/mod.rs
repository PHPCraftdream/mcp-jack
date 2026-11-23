//! Client-side rules of the modern profile that the spec assigns to SDK tests
//! (spec 04 section 8 exemption table): `C8` private-only caching, `C10` the
//! `tools/list` resync and `C12` the `events/list` resync.

mod cache;
mod flow;
mod resync;
