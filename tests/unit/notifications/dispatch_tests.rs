//! Tests for `crate::notifications::dispatch`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::notifications::channels::{NotificationChannel, parse_channels};
use ferrum_edge::notifications::{
    EventAction, Notification, NotificationField, Severity, dispatch,
};
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;

fn fixed_notification() -> Notification {
    Notification {
        title: "x".to_string(),
        body: "y".to_string(),
        severity: Severity::Info,
        event_action: EventAction::Info,
        source: None,
        subject_id: None,
        namespace: None,
        fired_at: chrono::Utc::now(),
        fields: vec![NotificationField::new("k", "v")],
    }
}

fn webhook_channel_to(url: String) -> Arc<NotificationChannel> {
    let map = parse_channels(&json!({
        "dispatch_test": {
            "type": "webhook",
            "url": url,
            "body_template": "{}",
        }
    }))
    .unwrap();
    map.into_values().next().unwrap()
}

async fn read_request_headers(socket: &mut TcpStream) {
    let mut request = Vec::new();
    let mut buf = [0; 1024];
    loop {
        let n = socket.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        request.extend_from_slice(&buf[..n]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") || request.len() > 8192 {
            break;
        }
    }
}

async fn spawn_counting_response_server(
    expected_requests: usize,
) -> (SocketAddr, Arc<AtomicUsize>, Arc<Notify>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());
    let server_count = Arc::clone(&count);
    let server_notify = Arc::clone(&notify);

    let handle = tokio::spawn(async move {
        for _ in 0..expected_requests {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request_headers(&mut socket).await;
            server_count.fetch_add(1, Ordering::SeqCst);
            server_notify.notify_waiters();
            socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        }
    });

    (addr, count, notify, handle)
}

async fn wait_for_request_count(count: &AtomicUsize, notify: &Notify, expected: usize) {
    let wait = async {
        loop {
            if count.load(Ordering::SeqCst) >= expected {
                break;
            }
            notify.notified().await;
        }
    };
    timeout(Duration::from_secs(2), wait)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {expected} notification dispatches"));
}

async fn wait_for_available_permits(sem: &Semaphore, expected: usize) {
    let wait = async {
        loop {
            if sem.available_permits() == expected {
                break;
            }
            tokio::task::yield_now().await;
        }
    };
    timeout(Duration::from_secs(2), wait)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {expected} available permits"));
}

#[tokio::test]
async fn dispatch_drops_when_semaphore_exhausted() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sem = Arc::new(Semaphore::new(0));
    let http = PluginHttpClient::default();
    let channel = webhook_channel_to(format!("http://{addr}/notify"));
    let notification = Arc::new(fixed_notification());

    dispatch(
        Arc::clone(&notification),
        &[Arc::clone(&channel)],
        &sem,
        &http,
        "test_caller",
    );

    assert_eq!(sem.available_permits(), 0);
    assert!(
        timeout(Duration::from_millis(150), listener.accept())
            .await
            .is_err(),
        "dispatch should not connect when the semaphore has no available permits"
    );
}

#[tokio::test]
async fn dispatch_spawns_task_when_permit_available() {
    let (addr, count, notify, server) = spawn_counting_response_server(1).await;
    let sem = Arc::new(Semaphore::new(1));
    let http = PluginHttpClient::default();
    let channel = webhook_channel_to(format!("http://{addr}/notify"));
    let notification = Arc::new(fixed_notification());

    dispatch(
        Arc::clone(&notification),
        &[Arc::clone(&channel)],
        &sem,
        &http,
        "test_caller",
    );

    wait_for_request_count(&count, &notify, 1).await;
    server.await.unwrap();
    wait_for_available_permits(&sem, 1).await;

    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(sem.available_permits(), 1);
}

#[tokio::test]
async fn dispatch_with_multiple_channels_sends_each() {
    let (addr, count, notify, server) = spawn_counting_response_server(3).await;
    let sem = Arc::new(Semaphore::new(8));
    let http = PluginHttpClient::default();
    let channel = webhook_channel_to(format!("http://{addr}/notify"));
    let notification = Arc::new(fixed_notification());

    dispatch(
        Arc::clone(&notification),
        &[
            Arc::clone(&channel),
            Arc::clone(&channel),
            Arc::clone(&channel),
        ],
        &sem,
        &http,
        "test_caller",
    );

    wait_for_request_count(&count, &notify, 3).await;
    server.await.unwrap();
    wait_for_available_permits(&sem, 8).await;

    assert_eq!(count.load(Ordering::SeqCst), 3);
    assert_eq!(sem.available_permits(), 8);
}
