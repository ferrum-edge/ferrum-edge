use std::io::Cursor;
use std::sync::Arc;
#[cfg(feature = "acme")]
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::Full;
use hyper::{Response, StatusCode};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use serde_json::{Value, json};
#[cfg(feature = "acme")]
use tracing::warn;
use uuid::Uuid;

use super::{AdminState, PaginationParams};
use crate::tls::acme::{AcmeCertificateRecord, AcmeError, AcmeIssuedCertificateInput};
#[cfg(feature = "acme")]
use crate::tls::acme::{
    AcmeDns01ChallengeRecord, AcmeHttp01ChallengeRecord, AcmeHttp01OrderInput, AcmeOrderRecord,
    AcmeOrderStatus, AcmeTlsAlpn01ChallengeRecord,
};
use crate::tls::managed::{ManagedTlsError, ManagedTlsMaterialKind, ManagedTlsRecord};

pub(super) async fn handle_inventory(
    state: &AdminState,
    pagination: &PaginationParams,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let inventory = collect_inventory(state);
    let body = super::paginate_response(&inventory.entries, pagination);
    Ok(super::json_response(StatusCode::OK, &body))
}

pub(super) fn collect_inventory(state: &AdminState) -> crate::tls::inventory::TlsInventory {
    let env_config = state
        .proxy_state
        .as_ref()
        .map(|proxy| proxy.env_config.as_ref());
    let config = state
        .proxy_state
        .as_ref()
        .map(|proxy| proxy.config.load_full())
        .or_else(|| {
            state
                .cached_config
                .as_ref()
                .map(|cached| cached.load_full())
        });
    crate::tls::inventory::TlsInventory::collect(env_config, config.as_deref())
}

pub(super) async fn handle_events(
    pagination: &PaginationParams,
    query: Option<&str>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let filter = match parse_event_filter(query) {
        Ok(filter) => filter,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    let events = crate::tls::events::global_event_log().list(&filter);
    let body = super::paginate_response(&events, pagination);
    Ok(super::json_response(StatusCode::OK, &body))
}

pub(super) async fn handle_list_managed(
    kind: ManagedTlsMaterialKind,
    pagination: &PaginationParams,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    let records = store.list(kind);
    let body = super::paginate_response(&records, pagination);
    Ok(super::json_response(StatusCode::OK, &body))
}

pub(super) async fn handle_list_acme_certificates(
    pagination: &PaginationParams,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let store = match acme_certificate_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    let records = store.list_certificates();
    let body = super::paginate_response(&records, pagination);
    Ok(super::json_response(StatusCode::OK, &body))
}

pub(super) async fn handle_get_acme_certificate(
    id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let store = match acme_certificate_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    match store.get_certificate(id) {
        Ok(record) => Ok(super::json_response(
            StatusCode::OK,
            &json!(record.summary()),
        )),
        Err(error) => Ok(acme_error_response(error)),
    }
}

pub(super) async fn handle_list_acme_orders(
    pagination: &PaginationParams,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let store = match acme_order_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    let records = store.list_orders();
    let body = super::paginate_response(&records, pagination);
    Ok(super::json_response(StatusCode::OK, &body))
}

pub(super) async fn handle_get_acme_order(id: &str) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let store = match acme_order_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    match store.get_order(id) {
        Ok(record) => Ok(super::json_response(
            StatusCode::OK,
            &json!(record.summary()),
        )),
        Err(error) => Ok(acme_error_response(error)),
    }
}

pub(super) async fn handle_list_acme_accounts(
    pagination: &PaginationParams,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let certificate_store = match acme_certificate_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    let order_store = match acme_order_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    let certificates = certificate_store.list_certificates();
    let persisted_accounts = match acme_account_store_response() {
        Ok(store) => store.list_accounts(),
        Err(_) => Vec::new(),
    };
    let accounts = order_store.list_accounts(&certificates, &persisted_accounts);
    let body = super::paginate_response(&accounts, pagination);
    Ok(super::json_response(StatusCode::OK, &body))
}

pub(super) async fn handle_get_managed(
    kind: ManagedTlsMaterialKind,
    id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    match store.get(id) {
        Ok(record) if record.kind == kind => Ok(super::json_response(
            StatusCode::OK,
            &json!(record.summary()),
        )),
        Ok(record) => Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({
                "error": format!(
                    "managed TLS record '{}' has kind {}, expected {}",
                    id,
                    record.kind.as_str(),
                    kind.as_str()
                )
            }),
        )),
        Err(error) => Ok(managed_error_response(error)),
    }
}

pub(super) async fn handle_create_certificate(
    state: &AdminState,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let request = match parse_json::<ManagedCertificateRequest>(body_bytes) {
        Ok(request) => request,
        Err(response) => return Ok(*response),
    };
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    let (record, overwrite) = match certificate_record_from_request(None, request, false) {
        Ok(value) => value,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    match store.upsert(record, overwrite) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::CREATED,
                &json!(record.summary()),
            ))
        }
        Err(error) => Ok(managed_error_response(error)),
    }
}

pub(super) async fn handle_update_certificate(
    state: &AdminState,
    id: &str,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let request = match parse_json::<ManagedCertificateRequest>(body_bytes) {
        Ok(request) => request,
        Err(response) => return Ok(*response),
    };
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    if let Err(response) =
        require_managed_record_kind(store.as_ref(), id, ManagedTlsMaterialKind::Certificate)
    {
        return Ok(response);
    }
    let (record, _) = match certificate_record_from_request(Some(id), request, true) {
        Ok(value) => value,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    match store.upsert(record, true) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::OK,
                &json!(record.summary()),
            ))
        }
        Err(error) => Ok(managed_error_response(error)),
    }
}

pub(super) async fn handle_create_ca_bundle(
    state: &AdminState,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let request = match parse_json::<ManagedCaBundleRequest>(body_bytes) {
        Ok(request) => request,
        Err(response) => return Ok(*response),
    };
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    let (record, overwrite) = match ca_bundle_record_from_request(None, request, false) {
        Ok(value) => value,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    match store.upsert(record, overwrite) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::CREATED,
                &json!(record.summary()),
            ))
        }
        Err(error) => Ok(managed_error_response(error)),
    }
}

pub(super) async fn handle_update_ca_bundle(
    state: &AdminState,
    id: &str,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let request = match parse_json::<ManagedCaBundleRequest>(body_bytes) {
        Ok(request) => request,
        Err(response) => return Ok(*response),
    };
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    if let Err(response) =
        require_managed_record_kind(store.as_ref(), id, ManagedTlsMaterialKind::CaBundle)
    {
        return Ok(response);
    }
    let (record, _) = match ca_bundle_record_from_request(Some(id), request, true) {
        Ok(value) => value,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    match store.upsert(record, true) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::OK,
                &json!(record.summary()),
            ))
        }
        Err(error) => Ok(managed_error_response(error)),
    }
}

pub(super) async fn handle_create_crl(
    state: &AdminState,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let request = match parse_json::<ManagedCrlRequest>(body_bytes) {
        Ok(request) => request,
        Err(response) => return Ok(*response),
    };
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    let (record, overwrite) = match crl_record_from_request(None, request, false) {
        Ok(value) => value,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    match store.upsert(record, overwrite) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::CREATED,
                &json!(record.summary()),
            ))
        }
        Err(error) => Ok(managed_error_response(error)),
    }
}

pub(super) async fn handle_update_crl(
    state: &AdminState,
    id: &str,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let request = match parse_json::<ManagedCrlRequest>(body_bytes) {
        Ok(request) => request,
        Err(response) => return Ok(*response),
    };
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    if let Err(response) =
        require_managed_record_kind(store.as_ref(), id, ManagedTlsMaterialKind::Crl)
    {
        return Ok(response);
    }
    let (record, _) = match crl_record_from_request(Some(id), request, true) {
        Ok(value) => value,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    match store.upsert(record, true) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::OK,
                &json!(record.summary()),
            ))
        }
        Err(error) => Ok(managed_error_response(error)),
    }
}

pub(super) async fn handle_create_ocsp_response(
    state: &AdminState,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let request = match parse_json::<ManagedOcspResponseRequest>(body_bytes) {
        Ok(request) => request,
        Err(response) => return Ok(*response),
    };
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    let (record, overwrite) = match ocsp_response_record_from_request(None, request, false) {
        Ok(value) => value,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    match store.upsert(record, overwrite) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::CREATED,
                &json!(record.summary()),
            ))
        }
        Err(error) => Ok(managed_error_response(error)),
    }
}

pub(super) async fn handle_update_ocsp_response(
    state: &AdminState,
    id: &str,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let request = match parse_json::<ManagedOcspResponseRequest>(body_bytes) {
        Ok(request) => request,
        Err(response) => return Ok(*response),
    };
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    if let Err(response) =
        require_managed_record_kind(store.as_ref(), id, ManagedTlsMaterialKind::OcspResponse)
    {
        return Ok(response);
    }
    let (record, _) = match ocsp_response_record_from_request(Some(id), request, true) {
        Ok(value) => value,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    match store.upsert(record, true) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::OK,
                &json!(record.summary()),
            ))
        }
        Err(error) => Ok(managed_error_response(error)),
    }
}

pub(super) async fn handle_create_jwks(
    state: &AdminState,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let request = match parse_json::<ManagedJwksRequest>(body_bytes) {
        Ok(request) => request,
        Err(response) => return Ok(*response),
    };
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    let (record, overwrite) = match jwks_record_from_request(None, request, false) {
        Ok(value) => value,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    match store.upsert(record, overwrite) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::CREATED,
                &json!(record.summary()),
            ))
        }
        Err(error) => Ok(managed_error_response(error)),
    }
}

pub(super) async fn handle_create_acme_certificate(
    state: &AdminState,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let request = match parse_json::<AcmeCertificateRequest>(body_bytes) {
        Ok(request) => request,
        Err(response) => return Ok(*response),
    };
    let store = match acme_certificate_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    let (record, overwrite) = match acme_certificate_record_from_request(None, request, false) {
        Ok(value) => value,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    match store.upsert_certificate(record, overwrite) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::CREATED,
                &json!(record.summary()),
            ))
        }
        Err(error) => Ok(acme_error_response(error)),
    }
}

pub(super) async fn handle_create_acme_order(
    state: &AdminState,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    #[cfg(not(feature = "acme"))]
    {
        let _ = body_bytes;
        Ok(super::json_response(
            StatusCode::NOT_IMPLEMENTED,
            &json!({"error": "ACME order creation requires the 'acme' Cargo feature"}),
        ))
    }

    #[cfg(feature = "acme")]
    {
        let request = match parse_json::<AcmeOrderRequest>(body_bytes) {
            Ok(request) => request,
            Err(response) => return Ok(*response),
        };
        let store = match acme_order_store_response() {
            Ok(store) => store,
            Err(response) => return Ok(*response),
        };
        let (record, overwrite) = match acme_order_record_from_request(request).await {
            Ok(value) => value,
            Err(error) => {
                return Ok(super::json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": error}),
                ));
            }
        };
        match store.upsert_order(record, overwrite) {
            Ok(record) => {
                persist_acme_account_credentials(&record);
                Ok(super::json_response(
                    StatusCode::CREATED,
                    &json!(record.summary()),
                ))
            }
            Err(error) => Ok(acme_error_response(error)),
        }
    }
}

pub(super) async fn handle_delete_acme_order(
    state: &AdminState,
    id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let store = match acme_order_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    match store.delete_order(id) {
        Ok(record) => Ok(super::json_response(
            StatusCode::OK,
            &json!({"deleted": true, "record": record.summary()}),
        )),
        Err(error) => Ok(acme_error_response(error)),
    }
}

pub(super) async fn handle_finalize_acme_order(
    state: &AdminState,
    id: &str,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    #[cfg(not(feature = "acme"))]
    {
        let _ = (id, body_bytes);
        Ok(super::json_response(
            StatusCode::NOT_IMPLEMENTED,
            &json!({"error": "ACME order finalization requires the 'acme' Cargo feature"}),
        ))
    }

    #[cfg(feature = "acme")]
    {
        let request = match parse_json_or_default::<AcmeOrderFinalizeRequest>(body_bytes) {
            Ok(request) => request,
            Err(response) => return Ok(*response),
        };
        let order_store = match acme_order_store_response() {
            Ok(store) => store,
            Err(response) => return Ok(*response),
        };
        let certificate_store = match acme_certificate_store_response() {
            Ok(store) => store,
            Err(response) => return Ok(*response),
        };
        let order = match order_store.get_order(id) {
            Ok(order) => order,
            Err(error) => return Ok(acme_error_response(error)),
        };
        let certificate_id = match acme_finalize_certificate_id(&order, &request) {
            Ok(certificate_id) => certificate_id,
            Err(error) => {
                return Ok(super::json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": error}),
                ));
            }
        };
        let account_credentials_json = match order
            .account_credentials_json
            .clone()
            .or_else(|| acme_account_credentials_for_order(&order))
        {
            Some(account_credentials_json) => account_credentials_json,
            None => {
                return Ok(super::json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": "ACME order does not have persisted account credentials"}),
                ));
            }
        };
        let Some(order_url) = order.order_url.clone() else {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": "ACME order does not have an order_url"}),
            ));
        };

        let complete_config = crate::tls::acme::client::CompleteAcmeHttp01OrderConfig {
            account_credentials_json: crate::tls::source::SecretString::new(
                account_credentials_json,
            ),
            order_url: order_url.clone(),
            poll_timeout: Duration::from_secs(
                request.poll_timeout_seconds.unwrap_or(60).clamp(1, 600),
            ),
        };
        let challenge_type = match acme_order_challenge_type(&order) {
            Ok(challenge_type) => challenge_type,
            Err(error) => {
                return Ok(super::json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": error}),
                ));
            }
        };
        let completed = match match challenge_type {
            AcmeChallengeType::Http01 => {
                crate::tls::acme::client::complete_http01_order(complete_config).await
            }
            AcmeChallengeType::TlsAlpn01 => {
                crate::tls::acme::client::complete_tls_alpn01_order(complete_config).await
            }
            AcmeChallengeType::Dns01 => {
                crate::tls::acme::client::complete_dns01_order(complete_config).await
            }
        } {
            Ok(completed) => completed,
            Err(error) => {
                persist_failed_acme_order(&order_store, order.clone(), error.to_string());
                return Ok(super::json_response(
                    StatusCode::BAD_GATEWAY,
                    &json!({"error": error.to_string()}),
                ));
            }
        };

        if let Err(error) = validate_cert_key_pair(
            &completed.cert_pem,
            &completed.key_pem,
            request.allow_expired,
            request
                .cert_expiry_warning_days
                .unwrap_or(crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS),
        ) {
            persist_failed_acme_order(&order_store, order.clone(), error.clone());
            return Ok(super::json_response(
                StatusCode::BAD_GATEWAY,
                &json!({"error": error}),
            ));
        }

        let certificate = match AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
            id: certificate_id.clone(),
            domains: order.domains.clone(),
            directory_url: order.directory_url.clone(),
            account_id: order.account_id.clone(),
            order_url: Some(order_url),
            cert_pem: completed.cert_pem,
            key_pem: completed.key_pem,
            chain_pem: None,
        }) {
            Ok(record) => record,
            Err(error) => {
                return Ok(super::json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": error.to_string()}),
                ));
            }
        };
        let certificate =
            match certificate_store.upsert_certificate(certificate, request.allow_overwrite) {
                Ok(record) => record,
                Err(error) => return Ok(acme_error_response(error)),
            };

        let mut updated_order = order;
        updated_order.certificate_id = Some(certificate_id);
        updated_order.status = AcmeOrderStatus::Valid;
        updated_order.error = None;
        let updated_order = match order_store.upsert_order(updated_order, true) {
            Ok(record) => record,
            Err(error) => return Ok(acme_error_response(error)),
        };
        persist_acme_account_credentials(&updated_order);
        request_managed_source_reloads();
        Ok(super::json_response(
            StatusCode::OK,
            &json!({
                "order": updated_order.summary(),
                "certificate": certificate.summary(),
            }),
        ))
    }
}

pub(super) async fn handle_update_acme_certificate(
    state: &AdminState,
    id: &str,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let request = match parse_json::<AcmeCertificateRequest>(body_bytes) {
        Ok(request) => request,
        Err(response) => return Ok(*response),
    };
    let store = match acme_certificate_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    if let Err(error) = store.get_certificate(id) {
        return Ok(acme_error_response(error));
    }
    let (record, _) = match acme_certificate_record_from_request(Some(id), request, true) {
        Ok(value) => value,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    match store.upsert_certificate(record, true) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::OK,
                &json!(record.summary()),
            ))
        }
        Err(error) => Ok(acme_error_response(error)),
    }
}

pub(super) async fn handle_delete_acme_certificate(
    state: &AdminState,
    id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let usage = acme_certificate_usage(state, id);
    if !usage.is_empty() {
        return Ok(super::json_response(
            StatusCode::CONFLICT,
            &json!({
                "error": "ACME certificate is still referenced",
                "id": id,
                "used_by": usage,
            }),
        ));
    }
    let store = match acme_certificate_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    match store.delete_certificate(id) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::OK,
                &json!({"deleted": true, "record": record.summary()}),
            ))
        }
        Err(error) => Ok(acme_error_response(error)),
    }
}

pub(super) async fn handle_renew_acme_certificate(
    state: &AdminState,
    certificate_id: &str,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    #[cfg(not(feature = "acme"))]
    {
        let _ = (certificate_id, body_bytes);
        Ok(super::json_response(
            StatusCode::NOT_IMPLEMENTED,
            &json!({"error": "ACME renewal requires the 'acme' Cargo feature"}),
        ))
    }

    #[cfg(feature = "acme")]
    {
        let request = match parse_json_or_default::<AcmeRenewRequest>(body_bytes) {
            Ok(request) => request,
            Err(response) => return Ok(*response),
        };
        let certificate_store = match acme_certificate_store_response() {
            Ok(store) => store,
            Err(response) => return Ok(*response),
        };
        let order_store = match acme_order_store_response() {
            Ok(store) => store,
            Err(response) => return Ok(*response),
        };
        let certificate = match certificate_store.get_certificate(certificate_id) {
            Ok(record) => record,
            Err(error) => return Ok(acme_error_response(error)),
        };
        let existing_order = match order_store.latest_order_for_certificate(certificate_id) {
            Ok(order) => order,
            Err(error) => return Ok(acme_error_response(error)),
        };
        let stored_account_credentials_json =
            certificate.account_id.as_deref().and_then(|account_id| {
                acme_account_credentials(&certificate.directory_url, account_id)
            });
        let existing_account_credentials_json = request
            .existing_account_credentials_json
            .or_else(|| existing_order.and_then(|order| order.account_credentials_json))
            .or(stored_account_credentials_json);
        let renewal_order_id = match request.id {
            Some(id) => optional_resource_id(Some(&id), "id").and_then(|value| {
                value.ok_or_else(|| "id must not be empty when provided".to_string())
            }),
            None => Ok(format!("renew-{}", Uuid::new_v4().simple())),
        };
        let renewal_order_id = match renewal_order_id {
            Ok(id) => id,
            Err(error) => {
                return Ok(super::json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": error}),
                ));
            }
        };
        let (record, overwrite) = match acme_order_record_from_request(AcmeOrderRequest {
            id: Some(renewal_order_id),
            certificate_id: Some(certificate_id.to_string()),
            domains: certificate.domains,
            directory_url: certificate.directory_url,
            contact: request.contact,
            terms_of_service_agreed: request.terms_of_service_agreed,
            challenge_type: request.challenge_type,
            existing_account_credentials_json,
            allow_overwrite: request.allow_overwrite,
        })
        .await
        {
            Ok(value) => value,
            Err(error) => {
                return Ok(super::json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": error}),
                ));
            }
        };
        match order_store.upsert_order(record, overwrite) {
            Ok(record) => {
                persist_acme_account_credentials(&record);
                Ok(super::json_response(
                    StatusCode::CREATED,
                    &json!(record.summary()),
                ))
            }
            Err(error) => Ok(acme_error_response(error)),
        }
    }
}

pub(super) async fn handle_update_jwks(
    state: &AdminState,
    id: &str,
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let request = match parse_json::<ManagedJwksRequest>(body_bytes) {
        Ok(request) => request,
        Err(response) => return Ok(*response),
    };
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    if let Err(response) =
        require_managed_record_kind(store.as_ref(), id, ManagedTlsMaterialKind::Jwks)
    {
        return Ok(response);
    }
    let (record, _) = match jwks_record_from_request(Some(id), request, true) {
        Ok(value) => value,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": error}),
            ));
        }
    };
    match store.upsert(record, true) {
        Ok(record) => {
            request_managed_source_reloads();
            Ok(super::json_response(
                StatusCode::OK,
                &json!(record.summary()),
            ))
        }
        Err(error) => Ok(managed_error_response(error)),
    }
}

pub(super) async fn handle_delete_managed(
    state: &AdminState,
    kind: ManagedTlsMaterialKind,
    id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }
    let usage = managed_record_usage(state, id);
    if let Some(response) = referenced_managed_delete_conflict(id, &usage) {
        return Ok(response);
    }
    let store = match managed_store_response() {
        Ok(store) => store,
        Err(response) => return Ok(*response),
    };
    match store.get(id) {
        Ok(record) if record.kind != kind => Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({
                "error": format!(
                    "managed TLS record '{}' has kind {}, expected {}",
                    id,
                    record.kind.as_str(),
                    kind.as_str()
                )
            }),
        )),
        Ok(_) => match store.delete(id) {
            Ok(record) => {
                request_managed_source_reloads();
                Ok(super::json_response(
                    StatusCode::OK,
                    &json!({"deleted": true, "record": record.summary()}),
                ))
            }
            Err(error) => Ok(managed_error_response(error)),
        },
        Err(error) => Ok(managed_error_response(error)),
    }
}

fn parse_event_filter(query: Option<&str>) -> Result<crate::tls::events::TlsEventFilter, String> {
    let mut filter = crate::tls::events::TlsEventFilter::default();
    let Some(query) = query else {
        return Ok(filter);
    };

    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let value = value.into_owned();
        validate_filter_value(&key, &value)?;
        match key.as_ref() {
            "cert_id" => filter.cert_id = Some(value),
            "source_id" => filter.source_id = Some(value),
            "surface" => filter.surface = Some(value),
            "outcome" => filter.outcome = Some(value),
            "since" => {
                let parsed = DateTime::parse_from_rfc3339(&value)
                    .map_err(|error| format!("invalid since timestamp: {error}"))?;
                filter.since = Some(parsed.with_timezone(&Utc));
            }
            _ => {}
        }
    }
    Ok(filter)
}

fn validate_filter_value(key: &str, value: &str) -> Result<(), String> {
    if value.len() > 512 {
        return Err(format!("{key} must not exceed 512 bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{key} must not contain control characters"));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct TlsValidateRequest {
    #[serde(default)]
    cert_pem: Option<String>,
    #[serde(default)]
    key_pem: Option<String>,
    #[serde(default)]
    ca_bundle_pem: Option<String>,
    #[serde(default)]
    crl_pem: Option<String>,
    #[serde(default)]
    allow_expired: bool,
    #[serde(default)]
    cert_expiry_warning_days: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ManagedCertificateRequest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    cert_pem: String,
    key_pem: String,
    #[serde(default)]
    chain_pem: Option<String>,
    #[serde(default)]
    allow_overwrite: bool,
    #[serde(default)]
    allow_expired: bool,
    #[serde(default)]
    cert_expiry_warning_days: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ManagedCaBundleRequest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    ca_bundle_pem: String,
    #[serde(default)]
    allow_overwrite: bool,
    #[serde(default)]
    allow_expired: bool,
    #[serde(default)]
    cert_expiry_warning_days: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ManagedCrlRequest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    crl_pem: String,
    #[serde(default)]
    allow_overwrite: bool,
}

#[derive(Debug, Deserialize)]
struct ManagedOcspResponseRequest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    ocsp_der_base64: String,
    #[serde(default)]
    allow_overwrite: bool,
}

#[derive(Debug, Deserialize)]
struct ManagedJwksRequest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    jwks_json: String,
    #[serde(default)]
    allow_overwrite: bool,
}

#[derive(Debug, Deserialize)]
struct AcmeCertificateRequest {
    #[serde(default)]
    id: Option<String>,
    domains: Vec<String>,
    directory_url: String,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    order_url: Option<String>,
    cert_pem: String,
    key_pem: String,
    #[serde(default)]
    chain_pem: Option<String>,
    #[serde(default)]
    allow_overwrite: bool,
    #[serde(default)]
    allow_expired: bool,
    #[serde(default)]
    cert_expiry_warning_days: Option<u64>,
}

#[cfg(feature = "acme")]
#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum AcmeChallengeType {
    #[default]
    Http01,
    TlsAlpn01,
    Dns01,
}

#[cfg(feature = "acme")]
#[derive(Debug, Deserialize)]
struct AcmeOrderRequest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    certificate_id: Option<String>,
    domains: Vec<String>,
    directory_url: String,
    #[serde(default)]
    contact: Vec<String>,
    #[serde(default)]
    terms_of_service_agreed: bool,
    #[serde(default)]
    challenge_type: AcmeChallengeType,
    #[serde(default)]
    existing_account_credentials_json: Option<String>,
    #[serde(default)]
    allow_overwrite: bool,
}

#[cfg(feature = "acme")]
#[derive(Debug, Deserialize, Default)]
struct AcmeOrderFinalizeRequest {
    #[serde(default)]
    certificate_id: Option<String>,
    #[serde(default)]
    poll_timeout_seconds: Option<u64>,
    #[serde(default)]
    allow_overwrite: bool,
    #[serde(default)]
    allow_expired: bool,
    #[serde(default)]
    cert_expiry_warning_days: Option<u64>,
}

#[cfg(feature = "acme")]
#[derive(Debug, Deserialize, Default)]
struct AcmeRenewRequest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    contact: Vec<String>,
    #[serde(default)]
    terms_of_service_agreed: bool,
    #[serde(default)]
    challenge_type: AcmeChallengeType,
    #[serde(default)]
    existing_account_credentials_json: Option<String>,
    #[serde(default)]
    allow_overwrite: bool,
}

pub(super) async fn handle_validate(
    body_bytes: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let request: TlsValidateRequest = match serde_json::from_slice(body_bytes) {
        Ok(request) => request,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"valid": false, "error": format!("Invalid JSON body: {error}")}),
            ));
        }
    };

    match validate_tls_material(&request) {
        Ok(response) => Ok(super::json_response(StatusCode::OK, &response)),
        Err(error) => Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"valid": false, "error": error}),
        )),
    }
}

pub(super) async fn handle_rotate(
    state: &AdminState,
    surface: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match requested_surfaces(surface) {
        Ok(RotateTarget::All) => {
            let accepted = crate::tls::source::subscription::request_all_material_set_reloads();
            let svid_revision = if gateway_svid_is_configured(state) {
                match force_reload_gateway_svid(state) {
                    Ok(revision) => Some(revision),
                    Err(response) => return Ok(*response),
                }
            } else {
                None
            };
            if accepted.is_empty() && svid_revision.is_none() {
                return Ok(super::json_response(
                    StatusCode::NOT_FOUND,
                    &json!({
                        "error": "No active TLS source reload watchers are registered and gateway SVID sources are not configured",
                        "available_surfaces": crate::tls::source::subscription::registered_material_set_reload_surfaces(),
                    }),
                ));
            }
            Ok(super::json_response(
                StatusCode::ACCEPTED,
                &json!({
                    "accepted": true,
                    "requested_surface": surface,
                    "surfaces": accepted,
                    "gateway_svid_revision": svid_revision,
                }),
            ))
        }
        Ok(RotateTarget::Watcher(normalized)) => {
            if crate::tls::source::subscription::request_material_set_reload(normalized) {
                return Ok(super::json_response(
                    StatusCode::ACCEPTED,
                    &json!({
                        "accepted": true,
                        "requested_surface": surface,
                        "surface": normalized,
                    }),
                ));
            }
            Ok(super::json_response(
                StatusCode::NOT_FOUND,
                &json!({
                    "error": format!("No active TLS source reload watcher is registered for surface '{surface}'"),
                    "requested_surface": surface,
                    "normalized_surface": normalized,
                    "available_surfaces": crate::tls::source::subscription::registered_material_set_reload_surfaces(),
                }),
            ))
        }
        Ok(RotateTarget::GatewaySvid) => match force_reload_gateway_svid(state) {
            Ok(revision) => Ok(super::json_response(
                StatusCode::ACCEPTED,
                &json!({
                    "accepted": true,
                    "requested_surface": surface,
                    "surface": "svid",
                    "gateway_svid_revision": revision,
                }),
            )),
            Err(response) => Ok(*response),
        },
        Err(error) => Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": error}),
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RotateTarget {
    All,
    Watcher(&'static str),
    GatewaySvid,
}

fn requested_surfaces(surface: &str) -> Result<RotateTarget, String> {
    match surface {
        "all" => Ok(RotateTarget::All),
        "frontend" | "proxy" | "proxy_https" => Ok(RotateTarget::Watcher("proxy_https")),
        "backend" | "backend_tls" => Ok(RotateTarget::Watcher("backend_tls")),
        "admin" | "admin_https" => Ok(RotateTarget::Watcher("admin_https")),
        "dtls" | "frontend_dtls" => Ok(RotateTarget::Watcher("dtls")),
        "db" | "database" | "database_tls" => Ok(RotateTarget::Watcher("database_tls")),
        "cp_grpc" | "cp_grpc_tls" => Ok(RotateTarget::Watcher("cp_grpc")),
        "dp_grpc" | "dp_grpc_tls" => Ok(RotateTarget::Watcher("dp_grpc")),
        "gateway_svid" | "svid" => Ok(RotateTarget::GatewaySvid),
        _ => Err(format!(
            "unsupported TLS rotation surface '{surface}'; use proxy_https, backend_tls, admin_https, dtls, database_tls, cp_grpc, dp_grpc, svid, or all"
        )),
    }
}

fn gateway_svid_is_configured(state: &AdminState) -> bool {
    state.proxy_state.as_ref().is_some_and(|proxy_state| {
        proxy_state.env_config.gateway_svid_cert_path.is_some()
            && proxy_state.env_config.gateway_svid_key_path.is_some()
            && proxy_state
                .env_config
                .gateway_svid_trust_bundle_path
                .is_some()
    })
}

fn force_reload_gateway_svid(state: &AdminState) -> Result<u64, Box<Response<Full<Bytes>>>> {
    let Some(proxy_state) = state.proxy_state.as_ref() else {
        return Err(Box::new(super::json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": "proxy state is unavailable in this mode; gateway SVID cannot be reloaded"}),
        )));
    };
    proxy_state.force_reload_gateway_svid().map_err(|error| {
        Box::new(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": error.to_string()}),
        ))
    })
}

fn validate_tls_material(request: &TlsValidateRequest) -> Result<Value, String> {
    if request.cert_pem.is_none()
        && request.key_pem.is_none()
        && request.ca_bundle_pem.is_none()
        && request.crl_pem.is_none()
    {
        return Err(
            "at least one of cert_pem/key_pem, ca_bundle_pem, or crl_pem must be provided"
                .to_string(),
        );
    }

    let warning_days = request
        .cert_expiry_warning_days
        .unwrap_or(crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS);
    let mut validated = serde_json::Map::new();

    match (&request.cert_pem, &request.key_pem) {
        (Some(cert_pem), Some(key_pem)) => {
            let cert_count =
                validate_cert_key_pair(cert_pem, key_pem, request.allow_expired, warning_days)?;
            validated.insert(
                "cert_key_pair".to_string(),
                json!({"valid": true, "certificate_count": cert_count}),
            );
        }
        (Some(_), None) => {
            return Err("key_pem is required when cert_pem is provided".to_string());
        }
        (None, Some(_)) => {
            return Err("cert_pem is required when key_pem is provided".to_string());
        }
        (None, None) => {}
    }

    if let Some(ca_bundle_pem) = request.ca_bundle_pem.as_deref() {
        let cert_count = validate_ca_bundle(ca_bundle_pem, request.allow_expired, warning_days)?;
        validated.insert(
            "ca_bundle".to_string(),
            json!({"valid": true, "certificate_count": cert_count}),
        );
    }

    if let Some(crl_pem) = request.crl_pem.as_deref() {
        let crl_count = validate_crl_bundle(crl_pem)?;
        validated.insert(
            "crl".to_string(),
            json!({"valid": true, "crl_count": crl_count}),
        );
    }

    Ok(json!({
        "valid": true,
        "validated": validated,
    }))
}

fn validate_cert_key_pair(
    cert_pem: &str,
    key_pem: &str,
    allow_expired: bool,
    warning_days: u64,
) -> Result<usize, String> {
    let cert_chain = parse_cert_chain("cert_pem", cert_pem)?;
    let key = parse_private_key("key_pem", key_pem)?;

    if !allow_expired {
        crate::tls::check_cert_expiry_from_pem_bytes(
            cert_pem.as_bytes(),
            "cert_pem",
            "inline-pem:<redacted>",
            warning_days,
        )
        .map_err(|error| error.to_string())?;
    }

    let versions = [&rustls::version::TLS13, &rustls::version::TLS12];
    let builder =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&versions)
            .map_err(|error| format!("failed to set TLS protocol versions: {error}"))?;
    let cert_count = cert_chain.len();
    builder
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|error| format!("cert_pem and key_pem do not form a valid pair: {error}"))?;

    Ok(cert_count)
}

fn validate_ca_bundle(
    ca_bundle_pem: &str,
    allow_expired: bool,
    warning_days: u64,
) -> Result<usize, String> {
    let certs = parse_cert_chain("ca_bundle_pem", ca_bundle_pem)?;
    if !allow_expired {
        crate::tls::check_cert_expiry_from_pem_bytes(
            ca_bundle_pem.as_bytes(),
            "ca_bundle_pem",
            "inline-pem:<redacted>",
            warning_days,
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(certs.len())
}

fn validate_crl_bundle(crl_pem: &str) -> Result<usize, String> {
    let crls = rustls_pemfile::crls(&mut Cursor::new(crl_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("crl_pem: failed to parse PEM CRLs: {error}"))?;
    if crls.is_empty() {
        return Err("crl_pem: no PEM CRLs found".to_string());
    }
    Ok(crls.len())
}

fn validate_ocsp_response_base64(value: &str) -> Result<usize, String> {
    use base64::Engine as _;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|error| format!("ocsp_der_base64 must be valid base64: {error}"))?;
    if bytes.is_empty() {
        return Err("ocsp_der_base64 must decode to non-empty DER bytes".to_string());
    }
    Ok(bytes.len())
}

fn parse_cert_chain(
    field: &'static str,
    pem: &str,
) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("{field}: failed to parse PEM certificates: {error}"))?;
    if certs.is_empty() {
        return Err(format!("{field}: no PEM certificates found"));
    }
    Ok(certs)
}

fn parse_private_key(field: &'static str, pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    rustls_pemfile::private_key(&mut Cursor::new(pem.as_bytes()))
        .map_err(|error| format!("{field}: failed to parse PEM private key: {error}"))?
        .ok_or_else(|| format!("{field}: no PEM private key found"))
}

fn managed_store_response()
-> Result<Arc<crate::tls::managed::ManagedTlsStore>, Box<Response<Full<Bytes>>>> {
    crate::tls::managed::global_store().map_err(|error| {
        Box::new(super::json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("managed TLS store is unavailable: {error}")}),
        ))
    })
}

fn acme_certificate_store_response()
-> Result<Arc<crate::tls::acme::AcmeCertificateStore>, Box<Response<Full<Bytes>>>> {
    crate::tls::acme::global_certificate_store().map_err(|error| {
        Box::new(super::json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("ACME certificate store is unavailable: {error}")}),
        ))
    })
}

fn acme_order_store_response()
-> Result<Arc<crate::tls::acme::AcmeOrderStore>, Box<Response<Full<Bytes>>>> {
    crate::tls::acme::global_order_store().map_err(|error| {
        Box::new(super::json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("ACME order store is unavailable: {error}")}),
        ))
    })
}

fn acme_account_store_response()
-> Result<Arc<crate::tls::acme::AcmeAccountStore>, Box<Response<Full<Bytes>>>> {
    crate::tls::acme::global_account_store().map_err(|error| {
        Box::new(super::json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": format!("ACME account store is unavailable: {error}")}),
        ))
    })
}

fn managed_error_response(error: ManagedTlsError) -> Response<Full<Bytes>> {
    let status = match &error {
        ManagedTlsError::NotFound(_) => StatusCode::NOT_FOUND,
        ManagedTlsError::AlreadyExists(_) | ManagedTlsError::KindConflict { .. } => {
            StatusCode::CONFLICT
        }
        ManagedTlsError::InvalidId(_)
        | ManagedTlsError::InvalidPath(_)
        | ManagedTlsError::MissingMaterial { .. }
        | ManagedTlsError::WrongKind { .. } => StatusCode::BAD_REQUEST,
        ManagedTlsError::Read(_) | ManagedTlsError::Write(_) | ManagedTlsError::Parse(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    super::json_response(status, &json!({"error": error.to_string()}))
}

fn acme_error_response(error: AcmeError) -> Response<Full<Bytes>> {
    let status = match &error {
        AcmeError::NotFound(_) => StatusCode::NOT_FOUND,
        AcmeError::OrderNotFound(_) => StatusCode::NOT_FOUND,
        AcmeError::AlreadyExists(_) => StatusCode::CONFLICT,
        AcmeError::OrderAlreadyExists(_) => StatusCode::CONFLICT,
        AcmeError::InvalidId(_)
        | AcmeError::InvalidDomain(_)
        | AcmeError::InvalidPath(_)
        | AcmeError::InvalidChallengeToken(_)
        | AcmeError::BlockedDirectoryUrl(_)
        | AcmeError::MissingMaterial { .. } => StatusCode::BAD_REQUEST,
        AcmeError::Read(_) | AcmeError::Write(_) | AcmeError::Parse(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    super::json_response(status, &json!({"error": error.to_string()}))
}

fn request_managed_source_reloads() {
    let _ = crate::tls::source::subscription::request_all_material_set_reloads();
}

fn parse_json<T>(body_bytes: &[u8]) -> Result<T, Box<Response<Full<Bytes>>>>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(body_bytes).map_err(|error| {
        Box::new(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Invalid JSON body: {error}")}),
        ))
    })
}

#[cfg(feature = "acme")]
fn parse_json_or_default<T>(body_bytes: &[u8]) -> Result<T, Box<Response<Full<Bytes>>>>
where
    T: for<'de> Deserialize<'de> + Default,
{
    if body_bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    parse_json(body_bytes)
}

fn certificate_record_from_request(
    path_id: Option<&str>,
    request: ManagedCertificateRequest,
    force_overwrite: bool,
) -> Result<(ManagedTlsRecord, bool), String> {
    let id = managed_request_id(path_id, request.id.as_deref())?;
    let name = managed_name(request.name.as_deref(), &id)?;
    let description = managed_description(request.description)?;
    let cert_pem = combine_cert_and_chain(&request.cert_pem, request.chain_pem.as_deref());
    validate_cert_key_pair(
        &cert_pem,
        &request.key_pem,
        request.allow_expired,
        request
            .cert_expiry_warning_days
            .unwrap_or(crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS),
    )?;
    Ok((
        ManagedTlsRecord::new_certificate(
            id,
            name,
            description,
            request.cert_pem,
            request.key_pem,
            request.chain_pem,
        ),
        force_overwrite || request.allow_overwrite,
    ))
}

fn ca_bundle_record_from_request(
    path_id: Option<&str>,
    request: ManagedCaBundleRequest,
    force_overwrite: bool,
) -> Result<(ManagedTlsRecord, bool), String> {
    let id = managed_request_id(path_id, request.id.as_deref())?;
    let name = managed_name(request.name.as_deref(), &id)?;
    let description = managed_description(request.description)?;
    validate_ca_bundle(
        &request.ca_bundle_pem,
        request.allow_expired,
        request
            .cert_expiry_warning_days
            .unwrap_or(crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS),
    )?;
    Ok((
        ManagedTlsRecord::new_ca_bundle(id, name, description, request.ca_bundle_pem),
        force_overwrite || request.allow_overwrite,
    ))
}

fn crl_record_from_request(
    path_id: Option<&str>,
    request: ManagedCrlRequest,
    force_overwrite: bool,
) -> Result<(ManagedTlsRecord, bool), String> {
    let id = managed_request_id(path_id, request.id.as_deref())?;
    let name = managed_name(request.name.as_deref(), &id)?;
    let description = managed_description(request.description)?;
    validate_crl_bundle(&request.crl_pem)?;
    Ok((
        ManagedTlsRecord::new_crl(id, name, description, request.crl_pem),
        force_overwrite || request.allow_overwrite,
    ))
}

fn ocsp_response_record_from_request(
    path_id: Option<&str>,
    request: ManagedOcspResponseRequest,
    force_overwrite: bool,
) -> Result<(ManagedTlsRecord, bool), String> {
    let id = managed_request_id(path_id, request.id.as_deref())?;
    let name = managed_name(request.name.as_deref(), &id)?;
    let description = managed_description(request.description)?;
    validate_ocsp_response_base64(&request.ocsp_der_base64)?;
    Ok((
        ManagedTlsRecord::new_ocsp_response(id, name, description, request.ocsp_der_base64),
        force_overwrite || request.allow_overwrite,
    ))
}

fn jwks_record_from_request(
    path_id: Option<&str>,
    request: ManagedJwksRequest,
    force_overwrite: bool,
) -> Result<(ManagedTlsRecord, bool), String> {
    let id = managed_request_id(path_id, request.id.as_deref())?;
    let name = managed_name(request.name.as_deref(), &id)?;
    let description = managed_description(request.description)?;
    validate_jwks_json(&request.jwks_json)?;
    Ok((
        ManagedTlsRecord::new_jwks(id, name, description, request.jwks_json),
        force_overwrite || request.allow_overwrite,
    ))
}

fn acme_certificate_record_from_request(
    path_id: Option<&str>,
    request: AcmeCertificateRequest,
    force_overwrite: bool,
) -> Result<(AcmeCertificateRecord, bool), String> {
    let id = managed_request_id(path_id, request.id.as_deref())?;
    let domains = normalize_acme_domains(request.domains)?;
    let directory_url =
        validated_optional_acme_string(Some(request.directory_url), "directory_url")?
            .ok_or_else(|| "directory_url must not be empty".to_string())?;
    // Validate the directory URL at the import boundary so the persisted value is
    // already trusted by the time the renewal scheduler reads it (defense in depth;
    // outbound order prep re-validates at the ACME client chokepoint).
    crate::tls::acme::validate_acme_directory_url_ssrf_policy(&directory_url)
        .map_err(|error| error.to_string())?;
    let account_id = validated_optional_acme_string(request.account_id, "account_id")?;
    let order_url = validated_optional_acme_string(request.order_url, "order_url")?;
    let cert_pem = combine_cert_and_chain(&request.cert_pem, request.chain_pem.as_deref());
    validate_cert_key_pair(
        &cert_pem,
        &request.key_pem,
        request.allow_expired,
        request
            .cert_expiry_warning_days
            .unwrap_or(crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS),
    )?;
    Ok((
        AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
            id,
            domains,
            directory_url,
            account_id,
            order_url,
            cert_pem: request.cert_pem,
            key_pem: request.key_pem,
            chain_pem: request.chain_pem,
        })
        .map_err(|error| error.to_string())?,
        force_overwrite || request.allow_overwrite,
    ))
}

#[cfg(feature = "acme")]
async fn acme_order_record_from_request(
    request: AcmeOrderRequest,
) -> Result<(AcmeOrderRecord, bool), String> {
    let id = managed_request_id(None, request.id.as_deref())?;
    let certificate_id = optional_resource_id(request.certificate_id.as_deref(), "certificate_id")?;
    let domains = normalize_acme_domains(request.domains)?;
    let directory_url =
        validated_optional_acme_string(Some(request.directory_url), "directory_url")?
            .ok_or_else(|| "directory_url must not be empty".to_string())?;
    // The ACME client (`client::prepare_order`) validates the directory URL against
    // SSRF policy at the outbound chokepoint below, so no separate check is needed here.
    let contact = normalize_acme_contact(request.contact)?;
    let existing_account_credentials_json = request
        .existing_account_credentials_json
        .map(crate::tls::source::SecretString::new);
    let challenge_type = request.challenge_type;
    let allow_overwrite = request.allow_overwrite;
    let order_config = crate::tls::acme::client::AcmeOrderConfig {
        account: crate::tls::acme::client::AcmeAccountConfig {
            directory_url: directory_url.clone(),
            contact,
            terms_of_service_agreed: request.terms_of_service_agreed,
            existing_credentials_json: existing_account_credentials_json,
        },
        domains: domains.clone(),
    };

    let prepared = match challenge_type {
        AcmeChallengeType::Http01 => crate::tls::acme::client::prepare_http01_order(order_config)
            .await
            .map_err(|error| error.to_string())?,
        AcmeChallengeType::TlsAlpn01 => {
            crate::tls::acme::client::prepare_tls_alpn01_order(order_config)
                .await
                .map_err(|error| error.to_string())?
        }
        AcmeChallengeType::Dns01 => crate::tls::acme::client::prepare_dns01_order(order_config)
            .await
            .map_err(|error| error.to_string())?,
    };

    let mut http01_challenges = Vec::new();
    let mut tls_alpn01_challenges = Vec::new();
    let mut dns01_challenges = Vec::new();
    for challenge in prepared.challenges {
        match challenge_type {
            AcmeChallengeType::Http01 => http01_challenges.push(AcmeHttp01ChallengeRecord {
                identifier: challenge.identifier,
                token: challenge.token,
                key_authorization: challenge.key_authorization,
            }),
            AcmeChallengeType::TlsAlpn01 => {
                tls_alpn01_challenges.push(AcmeTlsAlpn01ChallengeRecord {
                    identifier: challenge.identifier,
                    token: challenge.token,
                    key_authorization: challenge.key_authorization,
                });
            }
            AcmeChallengeType::Dns01 => dns01_challenges.push(AcmeDns01ChallengeRecord {
                identifier: challenge.identifier,
                token: challenge.token,
                key_authorization: challenge.key_authorization,
            }),
        }
    }

    Ok((
        AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
            id,
            certificate_id,
            domains: prepared.domains,
            directory_url,
            account_id: Some(prepared.account_id),
            account_credentials_json: Some(
                prepared
                    .account_credentials_json
                    .expose_secret()
                    .to_string(),
            ),
            order_url: Some(prepared.order_url),
            status: AcmeOrderStatus::PendingChallenges,
            http01_challenges,
            tls_alpn01_challenges,
            dns01_challenges,
            error: None,
        })
        .map_err(|error| error.to_string())?,
        allow_overwrite,
    ))
}

#[cfg(feature = "acme")]
fn acme_order_challenge_type(order: &AcmeOrderRecord) -> Result<AcmeChallengeType, String> {
    let mut challenge_type = None;
    if !order.http01_challenges.is_empty() {
        challenge_type = Some(AcmeChallengeType::Http01);
    }
    if !order.tls_alpn01_challenges.is_empty() {
        if challenge_type.is_some() {
            return Err("ACME order contains multiple challenge types".to_string());
        }
        challenge_type = Some(AcmeChallengeType::TlsAlpn01);
    }
    if !order.dns01_challenges.is_empty() {
        if challenge_type.is_some() {
            return Err("ACME order contains multiple challenge types".to_string());
        }
        challenge_type = Some(AcmeChallengeType::Dns01);
    }
    challenge_type.ok_or_else(|| "ACME order does not contain any challenges".to_string())
}

#[cfg(feature = "acme")]
fn persist_acme_account_credentials(order: &AcmeOrderRecord) {
    let (Some(account_id), Some(credentials_json)) = (
        order.account_id.as_deref(),
        order.account_credentials_json.as_deref(),
    ) else {
        return;
    };
    let Ok(store) = crate::tls::acme::global_account_store() else {
        warn!("ACME account store is unavailable; renewal will rely on order credentials");
        return;
    };
    if let Err(_error) = store.upsert_account(
        account_id.to_string(),
        order.directory_url.clone(),
        credentials_json.to_string(),
    ) {
        super::warn_persistence_failure_redacted("acme_account_credentials_persist");
    }
}

#[cfg(feature = "acme")]
fn acme_account_credentials_for_order(order: &AcmeOrderRecord) -> Option<String> {
    let account_id = order.account_id.as_deref()?;
    acme_account_credentials(&order.directory_url, account_id)
}

#[cfg(feature = "acme")]
fn acme_account_credentials(directory_url: &str, account_id: &str) -> Option<String> {
    let store = crate::tls::acme::global_account_store().ok()?;
    store
        .get_credentials(directory_url, account_id)
        .ok()
        .flatten()
}

fn normalize_acme_domains(domains: Vec<String>) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    for domain in domains {
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            return Err("domains must not contain empty entries".to_string());
        }
        if domain.len() > 253 {
            return Err(format!("domain '{domain}' exceeds 253 bytes"));
        }
        if domain
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err(format!(
                "domain '{domain}' must not contain whitespace or control characters"
            ));
        }
        if !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }
    if normalized.is_empty() {
        return Err("domains must contain at least one entry".to_string());
    }
    Ok(normalized)
}

#[cfg(feature = "acme")]
fn normalize_acme_contact(contact: Vec<String>) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    for value in contact {
        let value = value.trim().to_string();
        if value.is_empty() {
            continue;
        }
        if value.len() > 2048 {
            return Err("contact entries must not exceed 2048 bytes".to_string());
        }
        if value.chars().any(char::is_control) {
            return Err("contact entries must not contain control characters".to_string());
        }
        if !normalized.contains(&value) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

#[cfg(feature = "acme")]
fn optional_resource_id(
    value: Option<&str>,
    field: &'static str,
) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    crate::config::types::validate_resource_id(value)
        .map_err(|error| format!("{field}: {error}"))?;
    Ok(Some(value.to_string()))
}

#[cfg(feature = "acme")]
fn acme_finalize_certificate_id(
    order: &AcmeOrderRecord,
    request: &AcmeOrderFinalizeRequest,
) -> Result<String, String> {
    let requested = optional_resource_id(request.certificate_id.as_deref(), "certificate_id")?;
    if let Some(id) = requested {
        return Ok(id);
    }
    if let Some(id) = order.certificate_id.clone() {
        return Ok(id);
    }
    Ok(order.id.clone())
}

#[cfg(feature = "acme")]
fn persist_failed_acme_order(
    store: &crate::tls::acme::AcmeOrderStore,
    mut record: AcmeOrderRecord,
    error: String,
) {
    record.status = AcmeOrderStatus::Failed;
    record.error = Some(error);
    let _ = store.upsert_order(record, true);
}

fn validated_optional_acme_string(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 2048 {
        return Err(format!("{field} must not exceed 2048 bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{field} must not contain control characters"));
    }
    Ok(Some(value))
}

fn managed_request_id(path_id: Option<&str>, body_id: Option<&str>) -> Result<String, String> {
    let id = match (path_id, body_id) {
        (Some(path), Some(body)) if path != body => {
            return Err("body id must match path id".to_string());
        }
        (Some(path), _) => path.to_string(),
        (None, Some(body)) => body.to_string(),
        (None, None) => Uuid::new_v4().to_string(),
    };
    crate::config::types::validate_resource_id(&id)?;
    Ok(id)
}

fn managed_name(raw: Option<&str>, id: &str) -> Result<String, String> {
    let name = raw.unwrap_or(id).trim();
    if name.is_empty() {
        return Err("name must not be empty".to_string());
    }
    if name.len() > 256 {
        return Err("name must not exceed 256 bytes".to_string());
    }
    if name.chars().any(char::is_control) {
        return Err("name must not contain control characters".to_string());
    }
    Ok(name.to_string())
}

fn managed_description(raw: Option<String>) -> Result<Option<String>, String> {
    let Some(description) = raw else {
        return Ok(None);
    };
    let description = description.trim().to_string();
    if description.is_empty() {
        return Ok(None);
    }
    if description.len() > 2048 {
        return Err("description must not exceed 2048 bytes".to_string());
    }
    if description.chars().any(char::is_control) {
        return Err("description must not contain control characters".to_string());
    }
    Ok(Some(description))
}

fn combine_cert_and_chain(cert_pem: &str, chain_pem: Option<&str>) -> String {
    let Some(chain_pem) = chain_pem else {
        return cert_pem.to_string();
    };
    let mut combined = cert_pem.to_string();
    if !combined.ends_with('\n') {
        combined.push('\n');
    }
    combined.push_str(chain_pem);
    combined
}

fn validate_jwks_json(jwks_json: &str) -> Result<(), String> {
    let value: Value = serde_json::from_str(jwks_json)
        .map_err(|error| format!("jwks_json must be valid JSON: {error}"))?;
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| "jwks_json must contain a keys array".to_string())?;
    if keys.is_empty() {
        return Err("jwks_json keys array must not be empty".to_string());
    }
    Ok(())
}

fn managed_record_usage(
    state: &AdminState,
    id: &str,
) -> Vec<crate::tls::inventory::TlsInventoryUsage> {
    let needle_collection = format!("/{id}");
    let needle_short = format!("://{id}");
    collect_inventory(state)
        .entries
        .into_iter()
        .filter(|entry| {
            entry.source.kind == "managed"
                && (entry.source.identifier.contains(&needle_collection)
                    || entry.source.identifier.contains(&needle_short))
        })
        .flat_map(|entry| entry.used_by)
        .collect()
}

fn require_managed_record_kind(
    store: &crate::tls::managed::ManagedTlsStore,
    id: &str,
    kind: ManagedTlsMaterialKind,
) -> Result<ManagedTlsRecord, Response<Full<Bytes>>> {
    match store.get(id) {
        Ok(record) if record.kind == kind => Ok(record),
        Ok(record) => Err(super::json_response(
            StatusCode::CONFLICT,
            &json!({
                "error": format!(
                    "managed TLS record '{}' already exists as {}, cannot overwrite with {}",
                    id,
                    record.kind.as_str(),
                    kind.as_str()
                )
            }),
        )),
        Err(error) => Err(managed_error_response(error)),
    }
}

fn referenced_managed_delete_conflict(
    id: &str,
    usage: &[crate::tls::inventory::TlsInventoryUsage],
) -> Option<Response<Full<Bytes>>> {
    if usage.is_empty() {
        return None;
    }
    Some(super::json_response(
        StatusCode::CONFLICT,
        &json!({
            "error": "managed TLS record is still referenced",
            "id": id,
            "used_by": usage,
        }),
    ))
}

fn acme_certificate_usage(
    state: &AdminState,
    id: &str,
) -> Vec<crate::tls::inventory::TlsInventoryUsage> {
    let needle_collection = format!("/{id}");
    let needle_short = format!("://{id}");
    collect_inventory(state)
        .entries
        .into_iter()
        .filter(|entry| {
            entry.source.kind == "acme"
                && (entry.source.identifier.contains(&needle_collection)
                    || entry.source.identifier.contains(&needle_short))
        })
        .flat_map(|entry| entry.used_by)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated_cert_and_key() -> (String, String) {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-sign cert");
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn validate_accepts_matching_cert_and_key() {
        let (cert_pem, key_pem) = generated_cert_and_key();
        let request = TlsValidateRequest {
            cert_pem: Some(cert_pem),
            key_pem: Some(key_pem),
            ca_bundle_pem: None,
            crl_pem: None,
            allow_expired: false,
            cert_expiry_warning_days: Some(30),
        };

        let result = validate_tls_material(&request).expect("valid material");
        assert_eq!(result["valid"].as_bool(), Some(true));
        assert_eq!(
            result["validated"]["cert_key_pair"]["certificate_count"].as_u64(),
            Some(1)
        );
    }

    #[test]
    fn validate_rejects_missing_key_for_cert() {
        let (cert_pem, _) = generated_cert_and_key();
        let request = TlsValidateRequest {
            cert_pem: Some(cert_pem),
            key_pem: None,
            ca_bundle_pem: None,
            crl_pem: None,
            allow_expired: false,
            cert_expiry_warning_days: None,
        };

        let error = validate_tls_material(&request).expect_err("missing key rejected");
        assert!(error.contains("key_pem is required"));
    }

    #[test]
    fn requested_surfaces_normalizes_supported_aliases() {
        assert_eq!(
            requested_surfaces("frontend").unwrap(),
            RotateTarget::Watcher("proxy_https")
        );
        assert_eq!(
            requested_surfaces("admin").unwrap(),
            RotateTarget::Watcher("admin_https")
        );
        assert_eq!(
            requested_surfaces("backend").unwrap(),
            RotateTarget::Watcher("backend_tls")
        );
        assert_eq!(
            requested_surfaces("backend_tls").unwrap(),
            RotateTarget::Watcher("backend_tls")
        );
        assert_eq!(
            requested_surfaces("dtls").unwrap(),
            RotateTarget::Watcher("dtls")
        );
        assert_eq!(
            requested_surfaces("frontend_dtls").unwrap(),
            RotateTarget::Watcher("dtls")
        );
        assert_eq!(
            requested_surfaces("db").unwrap(),
            RotateTarget::Watcher("database_tls")
        );
        assert_eq!(
            requested_surfaces("database_tls").unwrap(),
            RotateTarget::Watcher("database_tls")
        );
        assert_eq!(
            requested_surfaces("cp_grpc").unwrap(),
            RotateTarget::Watcher("cp_grpc")
        );
        assert_eq!(
            requested_surfaces("cp_grpc_tls").unwrap(),
            RotateTarget::Watcher("cp_grpc")
        );
        assert_eq!(
            requested_surfaces("dp_grpc").unwrap(),
            RotateTarget::Watcher("dp_grpc")
        );
        assert_eq!(
            requested_surfaces("svid").unwrap(),
            RotateTarget::GatewaySvid
        );
        assert_eq!(
            requested_surfaces("gateway_svid").unwrap(),
            RotateTarget::GatewaySvid
        );
        assert_eq!(requested_surfaces("all").unwrap(), RotateTarget::All);
        assert!(requested_surfaces("bogus").is_err());
    }

    #[test]
    fn jwks_validation_requires_non_empty_keys_array() {
        assert!(validate_jwks_json(r#"{"keys":[{"kid":"one","kty":"RSA"}]}"#).is_ok());
        assert!(validate_jwks_json(r#"{"keys":[]}"#).is_err());
        assert!(validate_jwks_json(r#"{"not_keys":[]}"#).is_err());
    }

    #[test]
    fn ocsp_response_validation_requires_non_empty_base64_der() {
        use base64::Engine as _;

        let encoded = base64::engine::general_purpose::STANDARD.encode([1_u8, 2, 3]);
        assert_eq!(validate_ocsp_response_base64(&encoded), Ok(3));
        assert!(validate_ocsp_response_base64("").is_err());
        assert!(validate_ocsp_response_base64("not-base64!!").is_err());
    }

    #[test]
    fn acme_certificate_request_normalizes_domains_and_validates_material() {
        let (cert_pem, key_pem) = generated_cert_and_key();
        let request = AcmeCertificateRequest {
            id: Some("edge-cert".to_string()),
            domains: vec![" Localhost ".to_string(), "localhost".to_string()],
            directory_url: " https://acme-staging-v02.api.letsencrypt.org/directory ".to_string(),
            account_id: Some(" account-1 ".to_string()),
            order_url: None,
            cert_pem,
            key_pem,
            chain_pem: None,
            allow_overwrite: true,
            allow_expired: false,
            cert_expiry_warning_days: Some(30),
        };

        let (record, overwrite) =
            acme_certificate_record_from_request(None, request, false).expect("record");

        assert_eq!(record.id, "edge-cert");
        assert_eq!(record.domains, vec!["localhost".to_string()]);
        assert_eq!(
            record.directory_url,
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(record.account_id.as_deref(), Some("account-1"));
        assert!(overwrite);
    }

    #[test]
    fn typed_update_routes_reject_cross_kind_collisions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::tls::managed::ManagedTlsStore::open(dir.path()).expect("open store");
        store
            .upsert(
                ManagedTlsRecord::new_ca_bundle(
                    "shared".to_string(),
                    "Shared CA".to_string(),
                    None,
                    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
                        .to_string(),
                ),
                false,
            )
            .expect("seed ca bundle");

        let kinds = [
            ManagedTlsMaterialKind::Certificate,
            ManagedTlsMaterialKind::Crl,
            ManagedTlsMaterialKind::OcspResponse,
            ManagedTlsMaterialKind::Jwks,
        ];
        for kind in kinds {
            let response = require_managed_record_kind(&store, "shared", kind)
                .expect_err("cross-kind update must conflict");
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }

        require_managed_record_kind(&store, "shared", ManagedTlsMaterialKind::CaBundle)
            .expect("same-kind update remains allowed");

        let (cert_pem, key_pem) = generated_cert_and_key();
        let error = store
            .upsert(
                ManagedTlsRecord::new_certificate(
                    "shared".to_string(),
                    "Shared Cert".to_string(),
                    None,
                    cert_pem,
                    key_pem,
                    None,
                ),
                true,
            )
            .expect_err("create-with-overwrite cross-kind rejected");
        assert!(matches!(error, ManagedTlsError::KindConflict { .. }));
        assert_eq!(
            managed_error_response(error).status(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn referenced_delete_still_conflicts_while_same_kind_overwrite_is_allowed() {
        let usage = vec![crate::tls::inventory::TlsInventoryUsage {
            surface: "proxy_https".to_string(),
            role: "cert".to_string(),
            resource_type: "env".to_string(),
            resource_id: "FERRUM_FRONTEND_TLS_CERT_SOURCE".to_string(),
            field: "cert_source".to_string(),
        }];
        let conflict = referenced_managed_delete_conflict("shared", &usage)
            .expect("referenced delete must conflict");
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert!(referenced_managed_delete_conflict("shared", &[]).is_none());

        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::tls::managed::ManagedTlsStore::open(dir.path()).expect("open store");
        let (cert_pem, key_pem) = generated_cert_and_key();
        store
            .upsert(
                ManagedTlsRecord::new_certificate(
                    "shared".to_string(),
                    "Shared Cert".to_string(),
                    None,
                    cert_pem.clone(),
                    key_pem.clone(),
                    None,
                ),
                false,
            )
            .expect("seed certificate");
        store
            .upsert(
                ManagedTlsRecord::new_certificate(
                    "shared".to_string(),
                    "Shared Cert Rotated".to_string(),
                    None,
                    cert_pem,
                    key_pem,
                    None,
                ),
                true,
            )
            .expect("same-kind overwrite remains allowed for rotation");
        assert_eq!(
            store.get("shared").expect("rotated").name,
            "Shared Cert Rotated"
        );
    }
}
