//! Shared GatewayClass authority for translation and Gateway API status.
//!
//! A Gateway is Ferrum-managed only when the current authoritative snapshot
//! contains the referenced `GatewayClass` and that object's `spec.controllerName`
//! exactly matches Ferrum's controller. The class name spelling is never used
//! as a fallback, including the default name `ferrum`.

use serde_json::Value;

use super::K8sObject;

/// Gateway API controller identity Ferrum stamps on status it owns.
pub const FERRUM_GATEWAY_CONTROLLER_NAME: &str = "ferrum.io/gateway-controller";

/// Controller identity Ferrum stamps on the `status.parents[]` entries of
/// GAMMA routes, whose parent is a `Service` rather than a Gateway (issue
/// #7538). Mesh routing has no GatewayClass, so its status carries the mesh's
/// own controller name.
pub const FERRUM_MESH_CONTROLLER_NAME: &str = "ferrum.io/mesh-controller";

/// Observed `GatewayClass` ownership relative to Ferrum.
///
/// The three states stay distinct so an absent class cannot be confused with a
/// present Ferrum-owned class, and a present foreign class (including a
/// foreign-owned object named `ferrum`) cannot become ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayClassAuthority {
    /// The snapshot contains this GatewayClass and `controllerName` matches Ferrum.
    Owned,
    /// The snapshot contains this GatewayClass, but Ferrum does not own it.
    Foreign,
    /// No GatewayClass object with this name is present in the snapshot.
    Missing,
}

impl GatewayClassAuthority {
    /// Record authority from an observed cluster-scoped GatewayClass object.
    ///
    /// The object is present, so this never returns [`Self::Missing`]. A missing
    /// or non-matching `controllerName` is foreign, not Ferrum-owned.
    pub fn from_gateway_class(object: &K8sObject) -> Self {
        match object.spec.get("controllerName").and_then(Value::as_str) {
            Some(name) if name == FERRUM_GATEWAY_CONTROLLER_NAME => Self::Owned,
            _ => Self::Foreign,
        }
    }

    /// Resolve a Gateway's referenced class through a snapshot lookup.
    ///
    /// `lookup` returns `Some` only when the class object was observed.
    /// Absence, an empty `gatewayClassName`, or a missing field is [`Self::Missing`].
    pub fn for_gateway(gateway: &K8sObject, lookup: impl FnOnce(&str) -> Option<Self>) -> Self {
        let Some(class_name) = gateway.spec.get("gatewayClassName").and_then(Value::as_str) else {
            return Self::Missing;
        };
        if class_name.is_empty() {
            return Self::Missing;
        }
        lookup(class_name).unwrap_or(Self::Missing)
    }

    /// Whether Ferrum should program listeners and plan Gateway/Route status.
    #[must_use]
    pub const fn is_ferrum_owned(self) -> bool {
        matches!(self, Self::Owned)
    }
}
