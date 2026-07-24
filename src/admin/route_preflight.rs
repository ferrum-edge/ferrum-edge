//! Pre-body admin route classification for slowloris-safe early rejection.
//!
//! Unknown routes, disallowed methods, and insufficient roles are rejected
//! before the shared request-body collect so a low-privilege or probing client
//! cannot hold the admin task on an unused upload. Keep the tables here in
//! sync with the dispatch match in [`crate::admin::handle_admin_request`].

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Response, StatusCode};
use serde_json::json;

use crate::admin::audit::AuditActor;
use crate::admin::jwt_auth::AdminRole;
use crate::admin::{json_response, require_admin_role, tls_route_required_role};

/// How the shared body collector should treat this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminBodyPolicy {
    /// Collect up to `max_body_mib` MiB (then dispatch with the bytes).
    Collect { max_body_mib: usize },
    /// Discard any request body; handlers do not consume bytes.
    Discard,
}

/// Outcome of pre-body route classification.
#[derive(Debug)]
pub(crate) enum AdminRoutePreflight {
    /// Proceed under `policy` (role gate already satisfied when present).
    Proceed(AdminBodyPolicy),
    /// Return this response immediately after dropping the body receiver.
    Reject(Response<Full<Bytes>>),
}

/// Classify a post-auth admin route before reading the body.
///
/// `restore_max_body_mib` is the configured `/restore` cap; other body-reading
/// routes keep the historical 1 MiB default. API-spec POST/PUT are handled by
/// their own collectors and are reported as [`AdminBodyPolicy::Discard`] here
/// so the shared collector does not consume `req` first — callers must still
/// dispatch those arms before any shared collect.
pub(crate) fn classify_admin_route(
    method: &Method,
    segments: &[&str],
    auth: &AuditActor,
    restore_max_body_mib: usize,
) -> AdminRoutePreflight {
    if let Some(meta) = known_admin_route(method, segments, restore_max_body_mib) {
        if let Some(required) = meta.required_role
            && let Some(resp) = require_admin_role(auth, required)
        {
            return AdminRoutePreflight::Reject(resp);
        }
        return AdminRoutePreflight::Proceed(meta.policy);
    }

    if path_has_any_known_method(segments) {
        return AdminRoutePreflight::Reject(json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            &json!({"error": "Method Not Allowed"}),
        ));
    }

    AdminRoutePreflight::Reject(json_response(
        StatusCode::NOT_FOUND,
        &json!({"error": "Not Found"}),
    ))
}

#[derive(Clone, Copy)]
struct RouteMeta {
    required_role: Option<AdminRole>,
    policy: AdminBodyPolicy,
}

fn collect(max_body_mib: usize) -> AdminBodyPolicy {
    AdminBodyPolicy::Collect { max_body_mib }
}

fn discard() -> AdminBodyPolicy {
    AdminBodyPolicy::Discard
}

fn known_admin_route(
    method: &Method,
    segments: &[&str],
    restore_max_body_mib: usize,
) -> Option<RouteMeta> {
    // TLS routes keep their dedicated role table.
    if let Some(required) = tls_route_required_role(method, segments) {
        let policy = if matches!(*method, Method::POST | Method::PUT) {
            collect(1)
        } else {
            discard()
        };
        return Some(RouteMeta {
            required_role: Some(required),
            policy,
        });
    }

    match (method, segments) {
        // Proxies
        (&Method::GET, ["proxies"] | ["proxies", _]) => Some(RouteMeta {
            required_role: None,
            policy: discard(),
        }),
        (&Method::POST, ["proxies"])
        | (&Method::PUT, ["proxies", _])
        | (&Method::DELETE, ["proxies", _]) => Some(RouteMeta {
            required_role: Some(AdminRole::Operator),
            policy: if *method == Method::DELETE {
                discard()
            } else {
                collect(1)
            },
        }),

        // Consumers + credentials
        (&Method::GET, ["consumers"] | ["consumers", _]) => Some(RouteMeta {
            required_role: None,
            policy: discard(),
        }),
        (&Method::POST, ["consumers"])
        | (&Method::PUT, ["consumers", _])
        | (&Method::DELETE, ["consumers", _]) => Some(RouteMeta {
            required_role: Some(AdminRole::Admin),
            policy: if *method == Method::DELETE {
                discard()
            } else {
                collect(1)
            },
        }),
        (
            &Method::PUT | &Method::POST,
            ["consumers", _, "credentials", _],
        )
        | (
            &Method::DELETE,
            ["consumers", _, "credentials", _] | ["consumers", _, "credentials", _, _],
        ) => Some(RouteMeta {
            required_role: Some(AdminRole::Admin),
            policy: if *method == Method::DELETE {
                discard()
            } else {
                collect(1)
            },
        }),

        // Plugins
        (&Method::GET, ["plugins"]) => Some(RouteMeta {
            required_role: None,
            policy: discard(),
        }),
        (&Method::GET, ["plugins", "config"] | ["plugins", "config", _]) => Some(RouteMeta {
            required_role: None,
            policy: discard(),
        }),
        (&Method::POST, ["plugins", "config"])
        | (&Method::PUT, ["plugins", "config", _])
        | (&Method::DELETE, ["plugins", "config", _]) => Some(RouteMeta {
            required_role: Some(AdminRole::Operator),
            policy: if *method == Method::DELETE {
                discard()
            } else {
                collect(1)
            },
        }),

        // Upstreams
        (&Method::GET, ["upstreams"] | ["upstreams", _]) => Some(RouteMeta {
            required_role: None,
            policy: discard(),
        }),
        (&Method::POST, ["upstreams"])
        | (&Method::PUT, ["upstreams", _])
        | (&Method::DELETE, ["upstreams", _]) => Some(RouteMeta {
            required_role: Some(AdminRole::Operator),
            policy: if *method == Method::DELETE {
                discard()
            } else {
                collect(1)
            },
        }),

        // Batch / backup / restore / audit / namespaces
        (&Method::POST, ["batch"]) => Some(RouteMeta {
            required_role: Some(AdminRole::Admin),
            policy: collect(1),
        }),
        (&Method::GET, ["backup"]) => Some(RouteMeta {
            required_role: Some(AdminRole::Admin),
            policy: discard(),
        }),
        (&Method::POST, ["restore"]) => Some(RouteMeta {
            required_role: Some(AdminRole::Admin),
            policy: collect(restore_max_body_mib),
        }),
        (&Method::GET, ["audit"]) => Some(RouteMeta {
            required_role: Some(AdminRole::Admin),
            policy: discard(),
        }),
        (&Method::GET, ["namespaces"]) => Some(RouteMeta {
            required_role: None,
            policy: discard(),
        }),

        // Metrics / charges (post-auth)
        (
            &Method::GET,
            ["metrics", "runtime"]
            | ["admin", "metrics"]
            | ["charges"]
            | ["charges", "sink", "status"],
        ) => Some(RouteMeta {
            required_role: None,
            policy: discard(),
        }),

        // Mesh introspection
        (
            &Method::GET,
            ["mesh", "service-graph"]
            | ["mesh", "egress-scope"]
            | ["mesh", "federation"]
            | ["mesh", "runtime-overlay"]
            | ["mesh", "config-drift"]
            | ["mesh", "remote-clusters"]
            | ["mesh", "policy-denies", "recent"],
        ) => Some(RouteMeta {
            required_role: None,
            policy: discard(),
        }),
        (&Method::POST, ["mesh", "egress-scope", "test"]) => Some(RouteMeta {
            required_role: Some(AdminRole::Operator),
            policy: collect(1),
        }),

        // Cluster / capabilities / waypoint
        (&Method::GET, ["cluster"] | ["backend-capabilities"]) => Some(RouteMeta {
            required_role: None,
            policy: discard(),
        }),
        (&Method::POST, ["backend-capabilities", "refresh"]) => Some(RouteMeta {
            required_role: Some(AdminRole::Operator),
            // Refresh takes no body.
            policy: discard(),
        }),
        (&Method::GET, ["node-waypoint", "identities"] | ["service-waypoint", "services"]) => {
            Some(RouteMeta {
                required_role: None,
                policy: discard(),
            })
        }

        // API specs: body collected inside the dedicated handlers for
        // POST/PUT; GET/DELETE discard here. Role gates for mutating /
        // privileged reads are enforced by the caller before dispatch.
        (&Method::POST, ["api-specs"]) | (&Method::PUT, ["api-specs", _]) => Some(RouteMeta {
            required_role: Some(AdminRole::Admin),
            policy: discard(),
        }),
        (&Method::GET, ["api-specs"]) => Some(RouteMeta {
            required_role: None,
            policy: discard(),
        }),
        (&Method::GET, ["api-specs", _] | ["api-specs", "by-proxy", _])
        | (&Method::DELETE, ["api-specs", _]) => Some(RouteMeta {
            required_role: Some(AdminRole::Admin),
            policy: discard(),
        }),

        _ => None,
    }
}

/// True when `segments` is a known admin resource path for at least one method.
fn path_has_any_known_method(segments: &[&str]) -> bool {
    const METHODS: &[Method] = &[
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
        Method::HEAD,
    ];
    // restore_max_body_mib is irrelevant for existence checks.
    METHODS
        .iter()
        .any(|method| known_admin_route(method, segments, 1).is_some())
}
