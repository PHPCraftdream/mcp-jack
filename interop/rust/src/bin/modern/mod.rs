//! The modern interop matrix modes (interop/modern/contract.md sections 3-5),
//! declared by the interop bins: the `modern-server` executable here and the
//! `modern-client` one in the same tree. Both dispatch before the bins'
//! default flag parsers, because the modern flag set is different (contract
//! 3.1).

pub mod client;
pub mod handler;
pub mod proto;
pub mod scenarios;
pub mod server;

/// The `--mode` value of the command line, if any (`--mode x` or `--mode=x`).
///
/// Scanned before any parser runs and without validating anything else: the
/// modern flags would otherwise be rejected by the default parsers.
pub fn mode_from_args() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--mode=") {
            return Some(value.to_owned());
        }
        if arg == "--mode" {
            return args.next();
        }
    }
    None
}
