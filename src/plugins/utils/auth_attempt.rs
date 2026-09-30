use std::collections::{HashMap, HashSet};

use crate::plugins::{JwtAuthAttributeValue, RequestContext};

/// Request mutations derived while one authentication credential is being
/// verified. Nothing reaches the shared [`RequestContext`] until the same
/// attempt establishes an accepted principal.
#[derive(Default)]
pub struct AuthenticationAttempt {
    claim_headers: HashMap<String, String>,
    principal_metadata: HashMap<String, String>,
    mesh_request_auth_audiences: Option<Vec<String>>,
    mesh_request_auth_claims: HashMap<String, JwtAuthAttributeValue>,
    stripping_metadata: HashSet<String>,
    stripped_query_params: HashSet<String>,
    /// Opaque digest of the authority that verified this attempt's external
    /// identity (issuer, key source, directory). Committed together with that
    /// identity as its [`super::auth_flow::ExternalIdentityRealm`].
    identity_realm_authority: Option<[u8; 32]>,
}

impl AuthenticationAttempt {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stage_claim_header(&mut self, key: String, value: String) {
        self.claim_headers.insert(key, value);
    }

    pub fn stage_principal_metadata(&mut self, key: String, value: String) {
        self.principal_metadata.insert(key, value);
    }

    pub fn stage_mesh_request_auth_audiences(&mut self, audiences: Vec<String>) {
        self.mesh_request_auth_audiences = Some(audiences);
    }

    pub fn stage_mesh_request_auth_claim(&mut self, path: String, value: JwtAuthAttributeValue) {
        self.mesh_request_auth_claims.insert(path, value);
    }

    pub fn stage_stripping_metadata(&mut self, key: String) {
        self.stripping_metadata.insert(key);
    }

    pub fn stage_query_param_strip(&mut self, key: String, name: String) {
        self.stripping_metadata.insert(key);
        self.stripped_query_params.insert(name);
    }

    /// Stage the verifying-authority digest for the external identity this
    /// attempt may commit (see
    /// [`super::auth_flow::external_identity_realm_authority`]). Mechanisms
    /// that can accept the same subject string from more than one authority
    /// must stage one, so equal subjects from different authorities never
    /// name the same principal (`GHSA-wr96-j2c3-qh66`).
    pub fn stage_identity_realm_authority(&mut self, authority: [u8; 32]) {
        self.identity_realm_authority = Some(authority);
    }

    pub(super) fn identity_realm_authority(&self) -> Option<[u8; 32]> {
        self.identity_realm_authority
    }

    /// Commit state tied to the selected request principal. The first accepted
    /// attempt owns this state; later accepted instances cannot replace or mix
    /// claim headers, mesh claims, or identity metadata from that principal.
    pub(super) fn commit_principal_state(self, ctx: &mut RequestContext) {
        if !self.claim_headers.is_empty() {
            let pending = &mut ctx.plugin_state_mut().pending_claim_headers;
            for (key, value) in self.claim_headers {
                pending.entry(key).or_insert(value);
            }
        }
        for (key, value) in self.principal_metadata {
            ctx.metadata.entry(key).or_insert(value);
        }
        if ctx.mesh_request_auth_audiences.is_empty()
            && let Some(audiences) = self.mesh_request_auth_audiences
        {
            ctx.mesh_request_auth_audiences = audiences;
        }
        for (path, value) in self.mesh_request_auth_claims {
            ctx.mesh_request_auth_claims.entry(path).or_insert(value);
        }
    }

    /// Commit cleanup for a credential that authenticated successfully. This
    /// remains additive so a later accepted instance cannot erase cleanup that
    /// an earlier accepted instance already requested.
    pub(super) fn commit_credential_cleanup(&self, ctx: &mut RequestContext) {
        for key in &self.stripping_metadata {
            ctx.metadata
                .entry(key.clone())
                .or_insert_with(|| "true".to_string());
        }
        for name in &self.stripped_query_params {
            ctx.query_params.remove(name);
        }
    }
}
