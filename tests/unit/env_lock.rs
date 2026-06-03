//! Process-wide environment lock shared by every env-var-mutating unit test.
//!
//! `cargo test --test unit_tests` runs tests in parallel, so any two tests
//! that read or write the same `FERRUM_*` process env var must serialize
//! against a single mutex — otherwise one test's mutation races another's
//! read. Both the config env-var helper (`config::env_config_tests`) and the
//! identity guardrail tests (`identity::env_guard`) acquire THIS lock, so
//! e.g. an identity test toggling `FERRUM_MESH_PRODUCTION_MODE` can never
//! interleave with a config test that reads it through `EnvConfig::from_env()`.
#![allow(dead_code)] // used by sibling test modules

use std::sync::Mutex;

pub static ENV_LOCK: Mutex<()> = Mutex::new(());
