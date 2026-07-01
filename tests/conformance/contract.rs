//! Machine-readable GA product contract.
//!
//! `ga_contract.yaml` is the source of truth for the semantic GA rows the
//! conformance suite treats as prescriptive, plus the live datapath assertions
//! future Kubernetes suites must emit.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

const CONTRACT_YAML: &str = include_str!("ga_contract.yaml");
const SUPPORTED_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Contract {
    pub schema_version: u32,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Capability {
    pub id: String,
    pub display_name: String,
    pub maturity: ContractMaturity,
    pub topology: String,
    pub config_protocol: String,
    pub semantic_assertions: Vec<SemanticAssertion>,
    pub live_suite: String,
    pub live_assertions: Vec<String>,
    /// Present when this capability's declared live assertions cannot yet be
    /// emitted by its live suite (an architectural or staged gap). The
    /// live-artifact validator ([`super::live_contract`]) REPORTS these rows
    /// instead of enforcing them; the semantic assertions above remain fully
    /// GA-gated. The string must say why and where the work is tracked —
    /// removing it is the act of enrolling the row in the live gate.
    #[serde(default)]
    pub live_deferred: Option<String>,
    pub platform_profile: String,
    pub docs_anchor: String,
    pub owner: String,
    #[serde(default)]
    pub exclusions: Vec<String>,
    #[serde(default)]
    pub pr_path_filters: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContractMaturity {
    Ga,
    Beta,
    Experimental,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SemanticAssertion {
    pub category: String,
    pub feature: String,
}

impl Contract {
    pub(crate) fn ga_semantic_assertions(&self) -> Vec<&SemanticAssertion> {
        self.capabilities
            .iter()
            .filter(|capability| capability.maturity == ContractMaturity::Ga)
            .flat_map(|capability| capability.semantic_assertions.iter())
            .collect()
    }

    pub(crate) fn ga_capabilities(&self) -> Vec<&Capability> {
        self.capabilities
            .iter()
            .filter(|capability| capability.maturity == ContractMaturity::Ga)
            .collect()
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(format!(
                "unsupported ga_contract schema_version {}, expected {}",
                self.schema_version, SUPPORTED_SCHEMA_VERSION
            ));
        }
        if self.capabilities.is_empty() {
            return Err("ga_contract must declare at least one capability".to_string());
        }

        let mut capability_ids = BTreeSet::new();
        let mut semantic_ids = BTreeSet::new();
        for capability in &self.capabilities {
            require_non_empty("capability.id", &capability.id)?;
            require_non_empty("capability.display_name", &capability.display_name)?;
            require_non_empty("capability.topology", &capability.topology)?;
            require_non_empty("capability.config_protocol", &capability.config_protocol)?;
            require_non_empty("capability.live_suite", &capability.live_suite)?;
            require_non_empty("capability.platform_profile", &capability.platform_profile)?;
            require_non_empty("capability.docs_anchor", &capability.docs_anchor)?;
            require_non_empty("capability.owner", &capability.owner)?;
            if !capability_ids.insert(capability.id.as_str()) {
                return Err(format!(
                    "duplicate ga_contract capability id `{}`",
                    capability.id
                ));
            }

            if capability.maturity == ContractMaturity::Ga {
                if capability.semantic_assertions.is_empty() {
                    return Err(format!(
                        "GA capability `{}` must declare semantic_assertions",
                        capability.id
                    ));
                }
                if capability.live_assertions.is_empty() {
                    return Err(format!(
                        "GA capability `{}` must declare live_assertions",
                        capability.id
                    ));
                }
            }

            let mut capability_semantics = BTreeSet::new();
            for assertion in &capability.semantic_assertions {
                require_non_empty("semantic_assertion.category", &assertion.category)?;
                require_non_empty("semantic_assertion.feature", &assertion.feature)?;
                let key = (assertion.category.as_str(), assertion.feature.as_str());
                if !capability_semantics.insert(key) {
                    return Err(format!(
                        "capability `{}` declares duplicate semantic assertion `{}/{}`",
                        capability.id, assertion.category, assertion.feature
                    ));
                }
                if capability.maturity == ContractMaturity::Ga && !semantic_ids.insert(key) {
                    return Err(format!(
                        "GA semantic assertion `{}/{}` is declared by more than one capability",
                        assertion.category, assertion.feature
                    ));
                }
            }

            let mut live_ids = BTreeSet::new();
            for live_assertion in &capability.live_assertions {
                require_non_empty("live_assertion", live_assertion)?;
                if !live_ids.insert(live_assertion.as_str()) {
                    return Err(format!(
                        "capability `{}` declares duplicate live assertion `{}`",
                        capability.id, live_assertion
                    ));
                }
            }

            if let Some(reason) = &capability.live_deferred
                && reason.trim().is_empty()
            {
                return Err(format!(
                    "capability `{}` sets live_deferred with an empty reason — document why \
                     the live assertions cannot be emitted and where the work is tracked",
                    capability.id
                ));
            }
        }

        Ok(())
    }
}

pub(crate) fn load_contract() -> Result<Contract, String> {
    let contract: Contract = serde_yaml::from_str(CONTRACT_YAML)
        .map_err(|err| format!("failed to parse tests/conformance/ga_contract.yaml: {err}"))?;
    contract.validate()?;
    Ok(contract)
}

fn require_non_empty(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("ga_contract field `{field}` must not be empty"))
    } else {
        Ok(())
    }
}

#[test]
fn ga_contract_manifest_schema_is_valid() {
    load_contract().expect("ga_contract.yaml must be parseable and schema-valid");
}
