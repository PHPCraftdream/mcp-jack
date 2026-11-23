//! Client rules of the modern profile (spec 04 section 6): request `_meta` and
//! mirror headers (`C1`, `C2`), `x-mcp-header` validation and projection
//! (`C5`, `C6`, `C11`), era detection and the era flow (`C9`), the resync flows
//! (`C10`, `C12`) and private-only result caching (`C8`).
mod annotations;
mod clientera;
mod era;
pub(crate) mod flow;
mod mirrors;
mod projection;
mod resync;

pub use annotations::{collect_annotations, validate_annotations, Annotation, AnnotationError};
pub use clientera::ClientEra;
pub use era::{detect_era, EraAction, EraDetection, EraReason, VerifiedResponse};
pub use mirrors::{add_client_info, build_mirrors, MirrorError, Mirrors};
pub use projection::{
    project_arguments, text_of_value, EventCatalog, ProjectionError, ToolCatalog,
};
pub use resync::{CacheKey, ExchangeResponse, ModernExchange, PrivateResultCache, Resync};
