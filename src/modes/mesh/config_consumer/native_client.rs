use std::collections::HashMap;
use std::time::Duration;

use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tracing::{error, info, warn};

use super::common::{
    BACKOFF_INITIAL_SECS, MESH_CONFIG_GRPC_MAX_DECODING_MESSAGE_SIZE, jittered_backoff,
    refresh_dp_grpc_tls_config_if_changed, wait_for_shutdown, wait_optional_tls_reload,
};
use super::native_tls::{
    annotate_connect_error, observed_class_from_error, prepare_native_mesh_tls,
};
use super::stream_lifecycle::{
    MeshConfigStreamCredential, MeshStreamAttachment, MeshStreamAttempt, MeshStreamAttemptProgress,
    MeshStreamRetirement, MeshStreamTimings, MeshStreamTracker,
    configure_mesh_config_stream_endpoint, reconnect_backoff_after_attempt,
};
use super::update_validation::{
    MeshUpdateConsumer, MeshUpdateExpectation, MeshUpdateRejection, validate_mesh_config_update,
    validate_update_ferrum_version,
};
use crate::grpc::auth::MESH_LOCAL_SUBSCRIBE_AUDIENCE;
use crate::grpc::dp_client::{DpGrpcTlsConfig, DpGrpcTlsReload, GrpcJwtSecret};
use crate::grpc::proto::mesh_config_sync_client::MeshConfigSyncClient;
use crate::grpc::proto::{
    MeshConfigUpdate, MeshSliceRejectReason, MeshSliceStatusPhase, MeshSliceStatusReport,
    MeshSubscribeRequest,
};
use crate::modes::mesh::revision::MeshRevisionRejection;
use crate::modes::mesh::runtime::{
    MeshRuntimeState, MeshSliceInstall, MeshSliceRuntimeOutcome, MeshSliceRuntimeRejectReason,
};
use crate::modes::mesh::slice::MeshSlice;

/// Wire category for a proxy-runtime refusal (issue #4812).
///
/// The mapping is total and compile-time closed, so the control plane only ever
/// records a fixed label — the data plane never sends free rejection text.
const fn runtime_reject_reason_wire(reason: MeshSliceRuntimeRejectReason) -> MeshSliceRejectReason {
    match reason {
        MeshSliceRuntimeRejectReason::ConfigBuild => MeshSliceRejectReason::RuntimeConfigBuild,
        MeshSliceRuntimeRejectReason::ProxyRefused => MeshSliceRejectReason::RuntimeProxyRefused,
        MeshSliceRuntimeRejectReason::TrustUnusable => MeshSliceRejectReason::RuntimeTrustUnusable,
        MeshSliceRuntimeRejectReason::TlsReload => MeshSliceRejectReason::RuntimeTlsReload,
        MeshSliceRuntimeRejectReason::DtlsCandidate => MeshSliceRejectReason::RuntimeDtlsCandidate,
    }
}

/// Build the `ReportMeshSliceStatus` payload for a proxy-runtime verdict.
fn runtime_status_report(
    version: &str,
    session_token: &str,
    outcome: MeshSliceRuntimeOutcome,
) -> MeshSliceStatusReport {
    let reject_reason = match outcome.reject_reason() {
        Some(reason) => runtime_reject_reason_wire(reason),
        None => MeshSliceRejectReason::Unspecified,
    };
    MeshSliceStatusReport {
        version: version.to_string(),
        session_token: session_token.to_string(),
        phase: MeshSliceStatusPhase::Applied as i32,
        reject_reason: reject_reason as i32,
    }
}

/// What the native `MeshSubscribe` receive loop woke for.
///
/// The proxy-runtime verdict arrives on a side channel, not on the stream, so
/// it must NOT reset the stream's first-frame / first-slice / silence clocks:
/// a data plane whose control plane went quiet is not made live by its own
/// apply task.
enum NativeStreamEvent {
    Update(MeshConfigUpdate),
    RuntimeVerdict,
}

/// How many additional attempts a failed `ReportMeshSliceStatus` gets, each
/// piggybacked on a later frame of the same subscription (issue #3265). Bounded
/// so a partitioned or refusing control plane cannot turn ACK reporting into an
/// unbounded retry loop.
const STATUS_REPORT_RETRIES: u8 = 3;

/// Phase B shell for Ferrum-native MeshSubscribe consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeMeshClientConfig {
    pub node_id: String,
    pub namespace: String,
    pub workload_spiffe_id: Option<String>,
    pub waypoint_name: Option<String>,
    pub labels: HashMap<String, String>,
    pub ambient_udp_source_scoping: bool,
    /// This DP is a NodeWaypoint whose transparent inbound capture listener
    /// terminates direct plaintext for enrolled pods on its node (issue #3287),
    /// so it needs the dedicated cross-namespace capture destination/policy
    /// inventory. See `MeshSliceRequest::node_waypoint_capture_scoping`.
    pub node_waypoint_capture_scoping: bool,
    /// Shared CP-failover primary-retry interval
    /// (`FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`). When > 0 and connected to a
    /// fallback CP after a first slice is installed, the client proactively
    /// reconnects to the primary CP — matching the xDS client and the documented
    /// HA failback model. `0` disables proactive failback (the prior behaviour).
    pub primary_retry_secs: u64,
    /// Per-invocation stream timing policy (issue #3854). Production uses
    /// [`MeshStreamTimings::production`]; tests may compress it so first-frame
    /// and application-silence failover are provable inside bounded CI.
    pub timings: MeshStreamTimings,
}

/// Fixed-cardinality protocol label for the shared stream lifecycle.
pub(crate) const NATIVE_PROTOCOL_LABEL: &str = "native";

impl NativeMeshClientConfig {
    pub fn subscribe_request(&self, ferrum_version: &str) -> MeshSubscribeRequest {
        MeshSubscribeRequest {
            node_id: self.node_id.clone(),
            ferrum_version: ferrum_version.to_string(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone().unwrap_or_default(),
            labels: self.labels.clone(),
            waypoint_name: self.waypoint_name.clone().unwrap_or_default(),
            ambient_udp_source_scoping: self.ambient_udp_source_scoping,
            node_waypoint_capture_scoping: self.node_waypoint_capture_scoping,
            // Ordinary LOCAL mesh subscription: this data plane talks to its
            // own control plane and presents the distinct, fixed local-mesh
            // JWT audience. The CP rejects both missing audiences (legacy
            // clients) and remote-discovery audiences on this class.
            remote_discovery: false,
        }
    }
}

/// Maintain a live native `MeshSubscribe` stream with multi-CP failover.
///
/// Attempt classification, endpoint rotation, and backoff are the shared
/// [`super::stream_lifecycle`] policy (issue #3854): a remote clean EOF is an
/// endpoint failure that rotates to the next configured CP and grows the
/// bounded, jittered backoff, while shutdown, TLS reload, and proactive primary
/// failback are intentional local retirements that penalize nothing.
pub async fn start_native_mesh_client_with_shutdown(
    cp_urls: Vec<String>,
    jwt_secret: GrpcJwtSecret,
    config: NativeMeshClientConfig,
    state: MeshRuntimeState,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut tls_config: Option<DpGrpcTlsConfig>,
    tls_reload: Option<DpGrpcTlsReload>,
) {
    if cp_urls.is_empty() {
        error!("No CP URLs configured — cannot start native mesh client");
        return;
    }

    let mut current_cp_index = 0usize;
    let mut backoff_secs = BACKOFF_INITIAL_SECS;
    let mut last_tls_revision = tls_reload
        .as_ref()
        .map(|reload| *reload.revision_rx.borrow())
        .unwrap_or(0);
    // The native consumer's CP credential is minted (or read) fresh on every
    // connection attempt, so there is no long-lived external credential to
    // report here.
    let mut tracker = MeshStreamTracker::new(
        NATIVE_PROTOCOL_LABEL,
        MeshConfigStreamCredential::NotConfigured,
        config.timings,
    );
    state.set_config_stream_status(tracker.status(state.has_first_slice()));

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        cp_urls = cp_urls.len(),
        liveness_bound_secs = config.timings.liveness_bound_seconds(),
        "Native mesh client starting"
    );

    loop {
        if *shutdown_rx.borrow() {
            info!("Native mesh client shutting down");
            return;
        }
        refresh_dp_grpc_tls_config_if_changed(
            &mut tls_config,
            tls_reload.as_ref(),
            &cp_urls,
            &mut last_tls_revision,
        );

        let cp_url = &cp_urls[current_cp_index];
        let mut stream_shutdown_rx = shutdown_rx.clone();
        let is_fallback = current_cp_index != 0 && cp_urls.len() > 1;
        tracker.set_endpoint_index(current_cp_index);
        let should_retry_primary = is_fallback && config.primary_retry_secs > 0;
        let mut delivered_usable_state = false;
        let mut stream_established = false;
        let mut force_primary = false;
        // Shutdown is recorded as an intentional retirement rather than an
        // unobserved `return`, so `/metrics` distinguishes a clean stop from a
        // stream that simply vanished.
        let mut shutting_down = false;
        // On a fallback CP, arm failback after a first slice is available. The
        // fallback stream may itself deliver that first slice and then stay open
        // indefinitely, so the timer must wait inside this select instead of
        // being decided only before `connect_mesh_subscribe` starts.
        let result = if should_retry_primary {
            tokio::select! {
                result = connect_mesh_subscribe(
                    cp_url,
                    &jwt_secret,
                    &config,
                    &state,
                    tls_config.as_ref(),
                    MeshStreamAttemptProgress {
                        tracker: &mut tracker,
                        delivered_usable_state: &mut delivered_usable_state,
                        stream_established: &mut stream_established,
                    },
                ) => result,
                _ = wait_for_first_slice_then_primary_retry(
                    state.clone(),
                    Duration::from_secs(config.primary_retry_secs),
                ) => {
                    force_primary = true;
                    Ok(MeshStreamAttempt::LocalRetirement(MeshStreamRetirement::PrimaryRetry))
                }
                _ = wait_for_shutdown(&mut stream_shutdown_rx) => {
                    info!("Native mesh client shutting down");
                    shutting_down = true;
                    Ok(MeshStreamAttempt::LocalRetirement(MeshStreamRetirement::Shutdown))
                }
                _ = wait_optional_tls_reload(
                    tls_reload.as_ref().map(|reload| reload.revision_rx.clone()),
                    last_tls_revision,
                ) => {
                    Ok(MeshStreamAttempt::LocalRetirement(MeshStreamRetirement::TlsReload))
                }
            }
        } else {
            tokio::select! {
                result = connect_mesh_subscribe(
                    cp_url,
                    &jwt_secret,
                    &config,
                    &state,
                    tls_config.as_ref(),
                    MeshStreamAttemptProgress {
                        tracker: &mut tracker,
                        delivered_usable_state: &mut delivered_usable_state,
                        stream_established: &mut stream_established,
                    },
                ) => result,
                _ = wait_for_shutdown(&mut stream_shutdown_rx) => {
                    info!("Native mesh client shutting down");
                    shutting_down = true;
                    Ok(MeshStreamAttempt::LocalRetirement(MeshStreamRetirement::Shutdown))
                }
                _ = wait_optional_tls_reload(
                    tls_reload.as_ref().map(|reload| reload.revision_rx.clone()),
                    last_tls_revision,
                ) => {
                    Ok(MeshStreamAttempt::LocalRetirement(MeshStreamRetirement::TlsReload))
                }
            }
        };

        let attempt = match result {
            Ok(attempt) => {
                if attempt.is_endpoint_failure() {
                    warn!(
                        cp_url = %cp_url,
                        outcome = attempt.as_metric_label(),
                        "Native MeshSubscribe stream ended; rotating to the next configured CP"
                    );
                } else {
                    info!(
                        outcome = attempt.as_metric_label(),
                        "Retiring the native MeshSubscribe stream on a local lifecycle event"
                    );
                }
                attempt
            }
            Err(e) => {
                // A `RESOURCE_EXHAUSTED` subscribe status is the CP's stream
                // admission controller refusing this workload for
                // capacity/tenancy reasons (issue #4531). Classified BEFORE the
                // local-gate check: the CP is alive and answering, and its
                // status message names the exact budget to raise, so calling it
                // a transport failure would discard the only actionable detail.
                let admission_refusal = e
                    .downcast_ref::<tonic::Status>()
                    .filter(|status| status.code() == tonic::Code::ResourceExhausted);
                if let Some(status) = admission_refusal {
                    error!(
                        cp_url = %cp_url,
                        outcome = MeshStreamAttempt::AdmissionRefused.as_metric_label(),
                        status = %status.message(),
                        "Control plane REFUSED the native MeshSubscribe stream for \
                         capacity/tenancy reasons: it is reachable and answering, but a CP gRPC \
                         stream admission budget is saturated. Raise the budget named in the \
                         status message (the sizing unit is one stream per DP or per mesh \
                         workload) or add CP replicas"
                    );
                }
                // A refusal by a fail-closed local gate (subscription binding or
                // config-revision ordering) is about the CP's CONTENT, not its
                // transport; both still rotate, but the reason label differs.
                let attempt = if admission_refusal.is_some() {
                    MeshStreamAttempt::AdmissionRefused
                } else if e.downcast_ref::<MeshApplyError>().is_some() {
                    MeshStreamAttempt::PolicyRejected
                } else {
                    // `after_established` is what lets `/health` tell an
                    // ordinary dial refusal apart from an already-established
                    // transport going dark (the HTTP/2 PING-ack failure that
                    // detects a blackhole). It is observed, never assumed.
                    MeshStreamAttempt::TransportFailure {
                        delivered_usable_state,
                        after_established: stream_established,
                    }
                };
                // Keep the live native mTLS classifier's closed-set
                // `native_tls_class` field and connection-failed message while
                // still recording the shared stream-lifecycle outcome. An
                // admission refusal already logged its own operator-actionable
                // line above and is not a connection failure, so it is not
                // relabelled as one here.
                match observed_class_from_error(&e).filter(|_| admission_refusal.is_none()) {
                    Some(class) => {
                        error!(
                            cp_url = %cp_url,
                            outcome = attempt.as_metric_label(),
                            native_tls_class = class.as_str(),
                            error = %e,
                            "Native MeshSubscribe connection failed"
                        );
                    }
                    None if admission_refusal.is_none() => {
                        error!(
                            cp_url = %cp_url,
                            outcome = attempt.as_metric_label(),
                            error = %e,
                            "Native MeshSubscribe connection failed"
                        );
                    }
                    None => {}
                }
                attempt
            }
        };

        let disposition = tracker.record(attempt);
        if force_primary {
            current_cp_index = 0;
        } else if disposition.advance_endpoint {
            current_cp_index = (current_cp_index + 1) % cp_urls.len();
        }
        state.set_config_stream_status(tracker.status(state.has_first_slice()));
        if shutting_down {
            return;
        }

        if !attempt.is_endpoint_failure() {
            backoff_secs = BACKOFF_INITIAL_SECS;
            continue;
        }

        let (sleep_secs, next_secs) = reconnect_backoff_after_attempt(
            backoff_secs,
            disposition.increase_backoff,
            delivered_usable_state,
        );
        let sleep_duration = jittered_backoff(sleep_secs);
        let mut sleep_shutdown_rx = shutdown_rx.clone();
        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {}
            _ = wait_for_shutdown(&mut sleep_shutdown_rx) => {
                info!("Native mesh client shutting down");
                return;
            }
            _ = wait_optional_tls_reload(
                tls_reload.as_ref().map(|reload| reload.revision_rx.clone()),
                last_tls_revision,
            ) => {
                backoff_secs = BACKOFF_INITIAL_SECS;
                continue;
            }
        }
        backoff_secs = next_secs;
    }
}

async fn connect_mesh_subscribe(
    cp_url: &str,
    jwt_secret: &GrpcJwtSecret,
    config: &NativeMeshClientConfig,
    state: &MeshRuntimeState,
    tls_config: Option<&DpGrpcTlsConfig>,
    progress: MeshStreamAttemptProgress<'_>,
) -> Result<MeshStreamAttempt, anyhow::Error> {
    let MeshStreamAttemptProgress {
        tracker,
        delivered_usable_state,
        stream_established,
    } = progress;

    // Bounded transport liveness, shared with the two ADS consumers and with
    // the hardened DP ConfigSync client: HTTP/2 PING + TCP keepalive, kept alive
    // while idle so a blackholed established stream fails instead of hanging.
    let mut endpoint = configure_mesh_config_stream_endpoint(
        Channel::from_shared(cp_url.to_string())?,
        10,
        config.timings,
    );

    let mut tls_observer = None;
    if let Some(tls) = tls_config {
        let host = cp_url
            .parse::<http::Uri>()
            .ok()
            .and_then(|uri| uri.host().map(str::to_owned));
        let prepared = prepare_native_mesh_tls(tls, host.as_deref())?;
        let (next_endpoint, observer) = prepared.apply(endpoint)?;
        endpoint = next_endpoint;
        tls_observer = observer;
    }

    let channel = match endpoint.connect().await {
        Ok(channel) => channel,
        Err(error) => {
            return Err(annotate_connect_error(error, tls_observer.as_deref()));
        }
    };
    // With an externally issued token (`FERRUM_DP_CP_GRPC_TOKEN_FILE`) the
    // issuer — not this node — decides the `ns` and `aud` claims, so a mesh
    // node's token must be minted for the local-mesh subscribe audience by
    // whatever mints it. See `docs/cp_namespace_tenancy.md`.
    // External token files are read off-worker via mint_async (detached thread
    // + shared bounded regular-file reader). Never call sync mint() here.
    let auth_token = jwt_secret
        .mint_async(
            &config.node_id,
            Some(&config.namespace),
            Some(MESH_LOCAL_SUBSCRIBE_AUDIENCE),
        )
        .await?;
    let token: MetadataValue<_> = format!("Bearer {auth_token}").parse()?;

    #[allow(clippy::result_large_err)]
    let mut client =
        MeshConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        })
        .max_decoding_message_size(MESH_CONFIG_GRPC_MAX_DECODING_MESSAGE_SIZE);
    // Clone before subscribe so apply/reject can report ACK/NACK on the same
    // authenticated channel without tearing down the stream (issue #3265).
    let mut status_client = client.clone();

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        cp_url = %cp_url,
        "Connected to CP, subscribing for native mesh config"
    );

    let subscribe_request = config.subscribe_request(crate::FERRUM_VERSION);
    // Bind the consumer to the EXACT request this stream puts on the wire, so a
    // response can never be validated against a different subscription than the
    // one the CP was asked to serve.
    let consumer = NativeMeshConfigConsumer::new(
        state.clone(),
        MeshUpdateExpectation::from_subscribe_request(&subscribe_request),
    );
    let request = tonic::Request::new(subscribe_request);
    // The first-frame clock starts at the RPC-open await, not when headers
    // return: a CP can accept the authenticated request, keep HTTP/2 healthy,
    // and never send response headers. Dropping this select cancels the
    // in-flight open; nothing is detached. The same absolute Instant continues
    // until the first response frame.
    let attempt_started_at = tokio::time::Instant::now();
    let first_frame_deadline =
        tokio::time::sleep_until(attempt_started_at + config.timings.first_frame);
    tokio::pin!(first_frame_deadline);
    let mut stream = tokio::select! {
        biased;
        _ = &mut first_frame_deadline => {
            return Ok(MeshStreamAttempt::FirstFrameTimeout);
        }
        result = client.mesh_subscribe(request) => {
            result?.into_inner()
        }
    };
    // The streaming RPC is open: that is what `/health` means by `connected`,
    // and it is also the observation that lets a later transport failure be
    // attributed to an ESTABLISHED stream rather than to a dial refusal.
    *stream_established = true;
    tracker.set_attachment(MeshStreamAttachment::Established);
    state.set_config_stream_status(tracker.status(state.has_first_slice()));

    // A dropped ACK/NACK would otherwise leave the CP's slice-drift surface
    // reporting a false `sent_vs_acknowledged` divergence forever: nothing else
    // re-reports, and on a quiet config store no further publication follows.
    // Retain only the LAST failed report (a newer report supersedes an older
    // one) and retry it on the next frame — including the 60s heartbeat, which
    // bounds convergence without adding a timer. Retries are attempt-bounded,
    // and a report the CP explicitly refused is dropped immediately: it is no
    // longer admissible, so retrying it can only add load.
    let mut pending_status_report: Option<(MeshSliceStatusReport, u8)> = None;

    // ── issue #4812: report the RUNTIME verdict, not only the install ACK ──
    // Installing a slice only makes it the RECEIVED slice; the proxy runtime is
    // a second, independent gate. Subscribing here (after the stream is open)
    // marks any pre-existing verdict seen, so this stream never reports a
    // verdict for a slice a previous stream delivered. The report is bound to
    // the exact (version, session_token) THIS stream installed: a verdict for
    // any other generation is dropped rather than misattributed.
    let mut runtime_verdicts = state.subscribe_runtime_verdict();
    let mut runtime_verdicts_live = true;
    let mut last_installed: Option<(String, String)> = None;

    // ── issue #3854: bounded liveness for an ESTABLISHED stream ──
    // Clocks are absolute from `attempt_started_at` (the RPC-open await). They
    // are polled before `stream.message()` so an already-expired bound cannot
    // lose indefinitely to a continuously ready heartbeat or other frame.
    let first_slice_deadline =
        tokio::time::sleep_until(attempt_started_at + config.timings.first_slice);
    tokio::pin!(first_slice_deadline);
    let mut awaiting_first_frame = true;
    let mut awaiting_first_slice = !state.has_first_slice();
    // Application silence is only a liveness signal once this CP has actually
    // demonstrated it emits heartbeats. Against a CP that never does, the
    // stream is legitimately silent while idle and transport keepalive is the
    // correct (and sufficient) bound. Set true and never cleared.
    let mut heartbeats_observed = false;
    let mut last_stream_activity = tokio::time::Instant::now();
    let silence_deadline =
        tokio::time::sleep_until(last_stream_activity + config.timings.max_silence);
    tokio::pin!(silence_deadline);

    loop {
        let event = tokio::select! {
            biased;
            _ = &mut first_frame_deadline, if awaiting_first_frame => {
                return Ok(MeshStreamAttempt::FirstFrameTimeout);
            }
            _ = &mut first_slice_deadline, if awaiting_first_slice => {
                if state.has_first_slice() {
                    awaiting_first_slice = false;
                    continue;
                }
                return Ok(MeshStreamAttempt::FirstSliceTimeout);
            }
            _ = &mut silence_deadline, if heartbeats_observed => {
                warn!(
                    cp_url = %cp_url,
                    max_silence_secs = config.timings.max_silence.as_secs(),
                    "Native MeshSubscribe stream went silent past the heartbeat bound; failing over"
                );
                return Ok(MeshStreamAttempt::HeartbeatSilenceTimeout);
            }
            verdict = runtime_verdicts.changed(), if runtime_verdicts_live => {
                if verdict.is_err() {
                    // The publisher lives on the shared runtime state this
                    // client holds, so this is unreachable in production. Latch
                    // the arm off rather than spinning on a closed channel.
                    runtime_verdicts_live = false;
                }
                NativeStreamEvent::RuntimeVerdict
            }
            message = stream.message() => {
                match message {
                    Ok(Some(update)) => NativeStreamEvent::Update(update),
                    // A remote clean EOF is an endpoint failure, not success:
                    // it rotates the CP and grows the bounded backoff.
                    Ok(None) => return Ok(MeshStreamAttempt::RemoteEof),
                    Err(status) => return Err(anyhow::Error::new(status)),
                }
            }
        };

        let update = match event {
            NativeStreamEvent::RuntimeVerdict => {
                let verdict = runtime_verdicts.borrow_and_update().clone();
                if let Some(verdict) = verdict
                    && let Some((version, session_token)) = last_installed.as_ref()
                    && verdict.version == *version
                {
                    let report = runtime_status_report(version, session_token, verdict.outcome);
                    let retry_report = report.clone();
                    let sent = tokio::time::timeout(
                        config.timings.outbound,
                        status_client.report_mesh_slice_status(report),
                    )
                    .await
                    .unwrap_or_else(|_| Err(status_report_deadline_exceeded()));
                    if let Err(err) = sent {
                        warn!(
                            version = %version,
                            code = ?err.code(),
                            "Failed to report mesh slice runtime verdict to control plane"
                        );
                        pending_status_report = Some((retry_report, STATUS_REPORT_RETRIES));
                    } else {
                        pending_status_report = None;
                    }
                }
                // A side-channel verdict is not stream activity: the liveness
                // clocks below deliberately stay where the last frame left them.
                continue;
            }
            NativeStreamEvent::Update(update) => update,
        };
        awaiting_first_frame = false;
        last_stream_activity = tokio::time::Instant::now();
        silence_deadline
            .as_mut()
            .reset(last_stream_activity + config.timings.max_silence);

        if let Some((report, attempts_left)) = pending_status_report.take() {
            let version = report.version.clone();
            let retry_report = report.clone();
            let sent = tokio::time::timeout(
                config.timings.outbound,
                status_client.report_mesh_slice_status(report),
            )
            .await
            .unwrap_or_else(|_| Err(status_report_deadline_exceeded()));
            if let Err(err) = sent {
                let transient = matches!(
                    err.code(),
                    tonic::Code::Unavailable
                        | tonic::Code::DeadlineExceeded
                        | tonic::Code::ResourceExhausted
                        | tonic::Code::Unknown
                );
                let attempts_left = attempts_left.saturating_sub(1);
                if transient && attempts_left > 0 {
                    pending_status_report = Some((retry_report, attempts_left));
                }
                tracing::debug!(
                    version = %version,
                    code = ?err.code(),
                    retrying = pending_status_report.is_some(),
                    "Mesh slice status retry did not reach the control plane"
                );
            }
        }
        // Heartbeats are handled explicitly: they carry no slice, so they are
        // bound only to the CP compatibility contract and never reach the
        // install path.
        let applied = if update.heartbeat {
            heartbeats_observed = true;
            validate_update_ferrum_version(&update.ferrum_version, MeshUpdateConsumer::Native)
                .map(|()| None)
                .map_err(MeshApplyError::Update)
        } else {
            consumer.apply_update(&update).map(Some)
        };

        match applied {
            Ok(Some(slice)) => {
                *delivered_usable_state = true;
                awaiting_first_slice = false;
                // This exact stream installed usable state.
                tracker.record_usable_state();
                state.set_config_stream_status(tracker.status(state.has_first_slice()));
                info!(
                    node_id = %slice.node_id,
                    namespace = %slice.namespace,
                    version = %slice.version,
                    "Applied native MeshSubscribe update"
                );
                // Issue #4812: this is the INSTALL-time verdict only — the
                // slice is the received slice, not yet the serving generation.
                // Bind it to this stream's session so the runtime verdict that
                // follows can be reported against the same (version, session).
                last_installed = Some((slice.version.clone(), update.session_token.clone()));
                let report = MeshSliceStatusReport {
                    version: slice.version.clone(),
                    session_token: update.session_token.clone(),
                    phase: MeshSliceStatusPhase::Accepted as i32,
                    reject_reason: MeshSliceRejectReason::Unspecified as i32,
                };
                let retry_report = report.clone();
                // Issue #3854 round two: this unary RPC used to be awaited
                // inline with NO deadline. A control plane that simply never
                // answered it suspended the whole `MeshSubscribe` receive loop,
                // so the first-frame, first-slice, and heartbeat-silence bounds
                // stopped being enforced by a piece of BEST-EFFORT reporting.
                // A timeout surfaces as `DeadlineExceeded`, which the existing
                // transient classification already retries through the same
                // single-slot `pending_status_report` (so ACK/NACK ordering is
                // unchanged) — and, critically, returns control to the select.
                let sent = tokio::time::timeout(
                    config.timings.outbound,
                    status_client.report_mesh_slice_status(report),
                )
                .await
                .unwrap_or_else(|_| Err(status_report_deadline_exceeded()));
                if let Err(err) = sent {
                    warn!(
                        version = %slice.version,
                        code = ?err.code(),
                        "Failed to report mesh slice ACK to control plane"
                    );
                    pending_status_report = Some((retry_report, STATUS_REPORT_RETRIES));
                } else {
                    pending_status_report = None;
                }
            }
            Ok(None) => {
                tracing::debug!("Received native MeshSubscribe heartbeat");
            }
            Err(rejection) => {
                // Best-effort NACK so the CP drift surface can show why this
                // DP is not converging. Reporting must not mask the stream
                // disposition below.
                if !update.heartbeat && !update.version.trim().is_empty() {
                    // Install-stage refusal. The reason is a closed wire enum,
                    // never the local diagnostic text: `reason_label()` still
                    // drives this DP's own metric and log line.
                    let report = MeshSliceStatusReport {
                        version: update.version.clone(),
                        session_token: update.session_token.clone(),
                        phase: MeshSliceStatusPhase::Accepted as i32,
                        reject_reason: MeshSliceRejectReason::InstallRefused as i32,
                    };
                    let retry_report = report.clone();
                    let sent = tokio::time::timeout(
                        config.timings.outbound,
                        status_client.report_mesh_slice_status(report),
                    )
                    .await
                    .unwrap_or_else(|_| Err(status_report_deadline_exceeded()));
                    if let Err(err) = sent {
                        warn!(
                            version = %update.version,
                            code = ?err.code(),
                            "Failed to report mesh slice NACK to control plane"
                        );
                        pending_status_report = Some((retry_report, STATUS_REPORT_RETRIES));
                    } else {
                        pending_status_report = None;
                    }
                }
                // The rejection site already emitted the reason-labelled metric
                // and the sanitized diagnostic; last-good state is untouched
                // either way. A response that is not bound to this subscription
                // means the whole stream is wrong, so drop it and let multi-CP
                // failover pick another control plane (the reconnect path logs
                // the failure with this CP's URL). A config-revision rejection
                // (issue #2473) does the same for a different reason: this CP's
                // whole view is behind the accepted revision (or belongs to
                // another ordering domain), so staying attached would only let
                // it keep serving stale generations.
                if rejection.terminates_stream() {
                    return Err(anyhow::Error::new(rejection));
                }
                warn!(
                    cp_url = %cp_url,
                    reason = rejection.reason_label(),
                    "Ignoring invalid native MeshSubscribe update; keeping last-good slice"
                );
            }
        }
    }
}

/// The status this consumer synthesizes when a `ReportMeshSliceStatus` unary
/// RPC exceeds the bounded outbound window (issue #3854).
///
/// `DeadlineExceeded` is deliberate rather than cosmetic: the caller's existing
/// transient-retry classification already treats it as retryable, so a stalled
/// control plane produces the same bounded, ordered retry a slow one does —
/// while the receive loop regains control and its liveness bounds keep running.
fn status_report_deadline_exceeded() -> tonic::Status {
    tonic::Status::deadline_exceeded(
        "mesh slice status report exceeded the bounded outbound window",
    )
}

async fn wait_for_first_slice_then_primary_retry(state: MeshRuntimeState, interval: Duration) {
    state.wait_for_first_slice().await;
    tokio::time::sleep(interval).await;
}

/// Applies native `MeshSubscribe` updates into the shared mesh runtime state.
///
/// The consumer carries the subscription context the CP was asked to serve, so
/// every update is bound to that exact request before it can reach
/// `install_slice`.
#[derive(Clone)]
pub struct NativeMeshConfigConsumer {
    state: MeshRuntimeState,
    expected: MeshUpdateExpectation,
}

impl NativeMeshConfigConsumer {
    pub fn new(state: MeshRuntimeState, expected: MeshUpdateExpectation) -> Self {
        Self { state, expected }
    }

    pub fn state(&self) -> &MeshRuntimeState {
        &self.state
    }

    /// Validate a non-heartbeat update against the subscription and install it.
    ///
    /// Two fail-closed gates, both completing **before** any mutation, so a
    /// refused response leaves the previously installed slice serving untouched:
    ///
    /// 1. Subscription binding / envelope consistency
    ///    (`validate_mesh_config_update`, issue #2457).
    /// 2. Authoritative config-revision freshness
    ///    ([`MeshRuntimeState::install_slice`], issue #2473) — a slice older
    ///    than, or from a different ordering domain than, the accepted revision
    ///    is quarantined instead of installed.
    pub fn apply_update(&self, update: &MeshConfigUpdate) -> Result<MeshSlice, MeshApplyError> {
        let consumer = MeshUpdateConsumer::Native;
        let slice = validate_mesh_config_update(update, &self.expected, consumer)
            .map_err(MeshApplyError::Update)?;
        match self.state.install_slice(slice.clone()) {
            MeshSliceInstall::Installed => Ok(slice),
            MeshSliceInstall::Quarantined(rejection) => Err(MeshApplyError::Revision(rejection)),
        }
    }
}

/// Why a native `MeshSubscribe` frame did not become the live slice.
///
/// Splits the two fail-closed gates so the stream disposition of each stays
/// explicit: a binding/content failure follows the issue-#2457 split, while
/// every revision failure terminates the stream so multi-CP failover leaves the
/// lagging control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshApplyError {
    Update(MeshUpdateRejection),
    Revision(MeshRevisionRejection),
}

impl MeshApplyError {
    /// Bounded, compile-time metric/diagnostic label for the refusal.
    pub fn reason_label(&self) -> &'static str {
        match self {
            Self::Update(rejection) => rejection.reason().as_metric_label(),
            Self::Revision(rejection) => rejection.reason().as_metric_label(),
        }
    }

    pub fn terminates_stream(&self) -> bool {
        match self {
            Self::Update(rejection) => rejection.terminates_stream(),
            Self::Revision(rejection) => rejection.terminates_stream(),
        }
    }
}

impl std::fmt::Display for MeshApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Update(rejection) => write!(f, "{rejection}"),
            Self::Revision(rejection) => write!(f, "{rejection}"),
        }
    }
}

impl std::error::Error for MeshApplyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::dp_client::generate_dp_jwt_full;
    use crate::modes::mesh::config_consumer::update_validation::MeshUpdateRejectReason;

    fn test_client_config() -> NativeMeshClientConfig {
        NativeMeshClientConfig {
            node_id: "node-a".to_string(),
            namespace: "ferrum".to_string(),
            workload_spiffe_id: None,
            waypoint_name: None,
            labels: HashMap::new(),
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
            primary_retry_secs: 0,
            timings: MeshStreamTimings::production(),
        }
    }

    /// A consumer bound to exactly what `test_client_config` subscribes with.
    fn test_consumer(state: MeshRuntimeState) -> NativeMeshConfigConsumer {
        let request = test_client_config().subscribe_request(crate::FERRUM_VERSION);
        let expected = MeshUpdateExpectation::from_subscribe_request(&request);
        NativeMeshConfigConsumer::new(state, expected)
    }

    fn update_for(slice: &MeshSlice) -> MeshConfigUpdate {
        MeshConfigUpdate {
            version: slice.version.clone(),
            timestamp: 1,
            mesh_slice_json: serde_json::to_string(slice).expect("mesh slice serializes"),
            ferrum_version: crate::FERRUM_VERSION.to_string(),
            heartbeat: false,
            config_authority: slice
                .revision
                .as_ref()
                .map(|revision| revision.authority.clone())
                .unwrap_or_default(),
            config_sequence: slice
                .revision
                .as_ref()
                .map_or(0, |revision| revision.sequence),
            session_token: "test-session".to_string(),
        }
    }

    #[test]
    fn apply_update_installs_mesh_slice() {
        let state = MeshRuntimeState::new();
        let consumer = test_consumer(state.clone());
        let update = update_for(&MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "ferrum".to_string(),
            version: "v1".to_string(),
            ..MeshSlice::default()
        });

        let slice = consumer.apply_update(&update).expect("update applies");

        assert_eq!(slice.node_id, "node-a");
        assert!(state.has_first_slice());
        assert_eq!(
            state
                .snapshot()
                .as_ref()
                .as_ref()
                .map(|slice| slice.version.as_str()),
            Some("v1")
        );
    }

    /// The subscription binding is enforced by the consumer itself: a slice
    /// built for another node never reaches `install_slice`, so a DP with no
    /// slice yet stays sliceless rather than adopting foreign state.
    #[test]
    fn apply_update_rejects_wrong_node_before_install() {
        let state = MeshRuntimeState::new();
        let consumer = test_consumer(state.clone());
        let update = update_for(&MeshSlice {
            node_id: "node-b".to_string(),
            namespace: "ferrum".to_string(),
            version: "v1".to_string(),
            ..MeshSlice::default()
        });

        let rejection = consumer
            .apply_update(&update)
            .expect_err("a slice for another node must be rejected");

        assert_eq!(
            rejection.reason_label(),
            MeshUpdateRejectReason::NodeIdMismatch.as_metric_label()
        );
        assert!(rejection.terminates_stream());
        assert!(!state.has_first_slice());
        assert!(state.snapshot().as_ref().is_none());
    }

    #[test]
    fn native_update_rejects_empty_ferrum_version() {
        let rejection = validate_update_ferrum_version("", MeshUpdateConsumer::Native)
            .expect_err("empty ferrum_version must be rejected");

        assert_eq!(
            rejection.reason(),
            MeshUpdateRejectReason::MissingFerrumVersion
        );
    }

    #[test]
    fn native_update_accepts_current_ferrum_version() {
        validate_update_ferrum_version(crate::FERRUM_VERSION, MeshUpdateConsumer::Native)
            .expect("current ferrum_version should be compatible");
    }

    #[tokio::test]
    async fn primary_retry_waits_until_first_slice_on_fallback_stream() {
        let state = MeshRuntimeState::new();
        let retry = tokio::spawn(wait_for_first_slice_then_primary_retry(
            state.clone(),
            Duration::from_millis(1),
        ));

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            !retry.is_finished(),
            "timer must not run before the first slice arrives"
        );

        state.install_slice(MeshSlice {
            version: "first".to_string(),
            ..MeshSlice::default()
        });

        tokio::time::timeout(Duration::from_secs(1), retry)
            .await
            .expect("primary retry wait should complete after first slice")
            .expect("primary retry wait task should join");
    }

    #[test]
    fn native_config_carries_primary_retry_secs() {
        let config = NativeMeshClientConfig {
            node_id: "n".to_string(),
            namespace: "ferrum".to_string(),
            workload_spiffe_id: None,
            waypoint_name: None,
            labels: HashMap::new(),
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
            primary_retry_secs: 300,
            timings: MeshStreamTimings::production(),
        };
        assert_eq!(config.primary_retry_secs, 300);
    }

    #[test]
    fn mesh_client_self_minted_token_carries_namespace_and_local_audience() {
        let token = generate_dp_jwt_full(
            "test-secret",
            "node-a",
            "ferrum-edge-cp-dp",
            Some("tenant-a"),
            Some(MESH_LOCAL_SUBSCRIBE_AUDIENCE),
        )
        .expect("token should mint");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        validation.set_issuer(&["ferrum-edge-cp-dp"]);
        validation.set_audience(&[MESH_LOCAL_SUBSCRIBE_AUDIENCE]);
        let decoded = jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(b"test-secret"),
            &validation,
        )
        .expect("token should decode");

        assert_eq!(
            decoded.claims.get("ns").and_then(|value| value.as_str()),
            Some("tenant-a")
        );
        assert_eq!(
            decoded.claims.get("aud").and_then(|value| value.as_str()),
            Some(MESH_LOCAL_SUBSCRIBE_AUDIENCE)
        );
    }
}
