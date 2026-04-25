//! Pre-built failure scripts for scripted-backend tests.
//!
//! Phase 7 of the scripted-backend framework — the
//! [`catalog`] module exposes ~30 constructor functions for the most
//! common failure modes (refuse-connect, mid-stream reset, malformed
//! headers, expired TLS, QUIC refusal, slow link, etc.). Tests
//! compose them with [`crate::scaffolding`] backends and clients to
//! describe behavior in 5-10 LOC.
//!
//! See the doc on [`catalog`] for the full grouping.

#![allow(dead_code, unused_imports)] // Catalog: individual tests use subsets.

pub mod catalog;
