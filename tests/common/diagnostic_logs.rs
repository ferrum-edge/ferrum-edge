use std::sync::Arc;

// The interest floor is owned once per test binary at its crate root as
// `crate::diagnostic_test_interest` (`src/lib.rs` for the lib tests,
// `tests/integration_tests.rs` for the integration suite), so every capture in
// that binary shares one floor and the support file is compiled only once.

pub fn capture_logs<T>(action: impl FnOnce() -> T) -> (T, String) {
    struct Writer(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    crate::diagnostic_test_interest::ensure_interest_floor();
    let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = bytes.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || Writer(output.clone()))
        .finish();
    let result = tracing::subscriber::with_default(subscriber, action);
    let logs = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    (result, logs)
}

crate::diagnostic_test_interest::capture_regression!(capture_logs, tracing::Level::TRACE);
