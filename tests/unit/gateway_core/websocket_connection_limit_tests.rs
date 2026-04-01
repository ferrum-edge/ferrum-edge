use ferrum_edge::proxy::try_acquire_websocket_connection_permit;
use std::sync::Arc;

#[test]
fn websocket_connection_permit_is_optional() {
    let permit = try_acquire_websocket_connection_permit(None).unwrap();
    assert!(permit.is_none());
}

#[test]
fn websocket_connection_permit_rejects_when_limit_is_exhausted() {
    let limit = Arc::new(tokio::sync::Semaphore::new(1));
    let _first = try_acquire_websocket_connection_permit(Some(&limit))
        .unwrap()
        .expect("first permit should be available");

    let second = try_acquire_websocket_connection_permit(Some(&limit));
    assert!(second.is_err(), "second permit should be rejected");
}
