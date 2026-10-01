//! Kubernetes Projected Service Account Token (PSAT) attestor.
//!
//! Workloads inside K8s mount a JWT (the projected SA token) at a
//! well-known path inside their pod. They forward it to the workload API
//! either as a metadata bearer token (gRPC over UDS) or as a header on
//! HTTP-based attestation channels. The attestor then validates the JWT
//! against the K8s API server's `TokenReview` endpoint, which returns the
//! authoritative `{namespace, serviceaccount, pod}` triple.
//!
//! This implementation defers the actual TokenReview HTTP call to a
//! pluggable [`TokenReviewer`] so unit tests can mock it without spinning up
//! a real K8s cluster.
//!
//! ### SPIFFE ID template
//!
//! Operators configure how the validated triple maps to a SPIFFE ID via a
//! `{trust_domain}` / `{namespace}` / `{serviceaccount}` / `{pod}` template.
//! Default Istio-style template: `spiffe://{trust_domain}/ns/{namespace}/sa/{serviceaccount}`.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use super::{AttestError, Attestor, PeerInfo, WorkloadIdentity};
use crate::identity::spiffe::{SpiffeId, TrustDomain};

/// Result returned by a TokenReview call.
#[derive(Debug, Clone)]
pub struct TokenReviewResult {
    pub authenticated: bool,
    pub namespace: String,
    pub service_account: String,
    pub pod_name: Option<String>,
    pub pod_uid: Option<String>,
}

/// A pluggable adapter for `TokenReview` calls. Production wiring will use
/// the existing K8s service-discovery client; tests inject mocks.
#[allow(clippy::double_must_use)] // async-trait adds a bare #[must_use]
#[async_trait]
pub trait TokenReviewer: Send + Sync + 'static {
    async fn review(&self, token: &str) -> Result<TokenReviewResult, String>;
}

/// Configuration for the K8s PSAT attestor.
pub struct K8sPsatAttestorConfig {
    pub trust_domain: TrustDomain,
    /// SPIFFE ID template — see module docs.
    pub spiffe_id_template: String,
    pub reviewer: Arc<dyn TokenReviewer>,
    /// If non-empty, only namespaces in this allow-list are accepted.
    pub allowed_namespaces: Vec<String>,
    /// If non-empty, only service accounts in this allow-list are accepted.
    pub allowed_service_accounts: Vec<String>,
}

impl K8sPsatAttestorConfig {
    pub fn istio_default(trust_domain: TrustDomain, reviewer: Arc<dyn TokenReviewer>) -> Self {
        Self {
            trust_domain,
            spiffe_id_template: "spiffe://{trust_domain}/ns/{namespace}/sa/{serviceaccount}"
                .to_string(),
            reviewer,
            allowed_namespaces: Vec::new(),
            allowed_service_accounts: Vec::new(),
        }
    }
}

/// K8s PSAT attestor.
pub struct K8sPsatAttestor {
    config: K8sPsatAttestorConfig,
}

impl K8sPsatAttestor {
    pub fn new(config: K8sPsatAttestorConfig) -> Result<Self, AttestError> {
        if config.spiffe_id_template.is_empty() {
            return Err(AttestError::Config(
                "spiffe_id_template must not be empty".to_string(),
            ));
        }
        Ok(Self { config })
    }

    fn render_id(&self, review: &TokenReviewResult) -> Result<SpiffeId, AttestError> {
        // Defence-in-depth against TokenReview-response injection.
        //
        // We treat the K8s API as semi-trusted (it is the authority for the
        // {namespace, serviceaccount, pod} triple), but a poisoned or
        // mis-configured TokenReviewer must not be able to smuggle path
        // characters into the SPIFFE ID via the template substitution. A
        // namespace value like `evil/sa/admin` would otherwise produce a
        // perfectly valid — but wrong-shaped — SPIFFE ID after substitution.
        //
        // Validate each substituent against the DNS-1123 label grammar
        // (`[a-z0-9]([-a-z0-9]*[a-z0-9])?`, max 63 chars) before they reach
        // the template. K8s namespaces, ServiceAccounts and Pod names are
        // all DNS-1123 labels per the Kubernetes API conventions, so this
        // is a tight upper bound that does not reject any legitimate input.
        if !is_dns1123_label(&review.namespace) {
            return Err(AttestError::Failed(format!(
                "TokenReview namespace '{}' is not a valid DNS-1123 label",
                review.namespace
            )));
        }
        if !is_dns1123_label(&review.service_account) {
            return Err(AttestError::Failed(format!(
                "TokenReview service_account '{}' is not a valid DNS-1123 label",
                review.service_account
            )));
        }
        if let Some(ref pod) = review.pod_name
            && !pod.is_empty()
            && !is_dns1123_label(pod)
        {
            return Err(AttestError::Failed(format!(
                "TokenReview pod_name '{}' is not a valid DNS-1123 label",
                pod
            )));
        }

        let mut rendered = self.config.spiffe_id_template.clone();
        rendered = rendered.replace("{trust_domain}", self.config.trust_domain.as_str());
        rendered = rendered.replace("{namespace}", &review.namespace);
        rendered = rendered.replace("{serviceaccount}", &review.service_account);
        rendered = rendered.replace("{pod}", review.pod_name.as_deref().unwrap_or(""));
        SpiffeId::new(rendered)
            .map_err(|e| AttestError::Failed(format!("rendered SPIFFE ID is invalid: {}", e)))
    }
}

/// DNS-1123 label per Kubernetes API conventions:
/// `[a-z0-9]([-a-z0-9]*[a-z0-9])?`, max 63 characters.
fn is_dns1123_label(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    let bytes = s.as_bytes();
    let valid_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !valid_alnum(bytes[0]) || !valid_alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.iter().all(|b| valid_alnum(*b) || *b == b'-')
}

#[async_trait]
impl Attestor for K8sPsatAttestor {
    fn kind(&self) -> &'static str {
        "k8s_psat"
    }

    async fn attest(&self, peer: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
        let token = match peer.bearer_token.as_ref() {
            Some(t) if !t.trim().is_empty() => t,
            _ => return Err(AttestError::NotApplicable),
        };

        let review = self
            .config
            .reviewer
            .review(token)
            .await
            .map_err(AttestError::Failed)?;

        if !review.authenticated {
            return Err(AttestError::Failed(
                "TokenReview marked the projected SA token as unauthenticated".to_string(),
            ));
        }
        if !self.config.allowed_namespaces.is_empty()
            && !self
                .config
                .allowed_namespaces
                .iter()
                .any(|ns| ns == &review.namespace)
        {
            return Err(AttestError::Failed(format!(
                "namespace '{}' is not in the allow-list",
                review.namespace
            )));
        }
        if !self.config.allowed_service_accounts.is_empty()
            && !self
                .config
                .allowed_service_accounts
                .iter()
                .any(|sa| sa == &review.service_account)
        {
            return Err(AttestError::Failed(format!(
                "serviceaccount '{}' is not in the allow-list",
                review.service_account
            )));
        }

        let id = self.render_id(&review)?;

        let mut selectors = HashMap::new();
        selectors.insert("k8s:namespace".to_string(), review.namespace.clone());
        selectors.insert(
            "k8s:serviceaccount".to_string(),
            review.service_account.clone(),
        );
        if let Some(pod) = review.pod_name.clone() {
            selectors.insert("k8s:pod".to_string(), pod);
        }
        if let Some(uid) = review.pod_uid.clone() {
            selectors.insert("k8s:pod-uid".to_string(), uid);
        }

        Ok(WorkloadIdentity {
            spiffe_id: id,
            selectors,
            attestor_kind: self.kind().to_string(),
        })
    }
}
