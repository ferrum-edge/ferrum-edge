//! Admin API for OpenAPI/Swagger spec ingestion + retrieval.
//!
//! v1 supports OpenAPI 2.0 (Swagger), 3.0.x, 3.1.x, 3.2.x in JSON or YAML.

pub mod extractor;
pub mod handlers;

pub use extractor::{
    ExtractError, ExtractedBundle, SpecFormat, SpecMetadata, extract, hash_resource_bundle,
};
