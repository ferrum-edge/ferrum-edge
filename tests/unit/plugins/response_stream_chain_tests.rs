//! Tests for how a chain of response stream inspectors runs a deferred cut:
//! the bytes an inspector cleared before it cut pass every later inspector,
//! and the terminal payload follows what they released.

use bytes::Bytes;
use ferrum_edge::plugins::{
    ResponseStreamAction, ResponseStreamInspector, chain_response_stream_inspectors,
};
use std::sync::{Arc, Mutex};

/// Releases every byte before its `trigger`, then defers a cut with
/// `payload`; the trigger and later bytes never leave. With `hold`, it
/// releases nothing until its flush, which cuts the held bytes the same way.
struct DeferringCutter {
    trigger: u8,
    payload: Option<&'static [u8]>,
    hold: bool,
    held: Vec<u8>,
    cut: bool,
    deferred: Option<Option<Bytes>>,
}

impl DeferringCutter {
    fn new(trigger: u8, payload: Option<&'static [u8]>) -> Self {
        Self {
            trigger,
            payload,
            hold: false,
            held: Vec::new(),
            cut: false,
            deferred: None,
        }
    }

    fn holding(trigger: u8, payload: Option<&'static [u8]>) -> Self {
        Self {
            hold: true,
            ..Self::new(trigger, payload)
        }
    }

    fn release(&mut self, bytes: &[u8]) -> ResponseStreamAction {
        if self.cut {
            return ResponseStreamAction::Forward(Bytes::new());
        }
        let Some(at) = bytes.iter().position(|&byte| byte == self.trigger) else {
            return ResponseStreamAction::Forward(Bytes::copy_from_slice(bytes));
        };
        self.cut = true;
        self.deferred = Some(self.payload.map(Bytes::from_static));
        ResponseStreamAction::Forward(Bytes::copy_from_slice(&bytes[..at]))
    }
}

#[async_trait::async_trait]
impl ResponseStreamInspector for DeferringCutter {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if self.hold {
            self.held.extend_from_slice(chunk);
            return ResponseStreamAction::Forward(Bytes::new());
        }
        self.release(chunk)
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        let held = std::mem::take(&mut self.held);
        self.release(&held)
    }

    fn has_deferred_cut(&self) -> bool {
        self.deferred.is_some()
    }

    fn take_deferred_cut(&mut self, client_line_open: bool) -> Option<Bytes> {
        let payload = self.deferred.take().flatten()?;
        if !client_line_open {
            return Some(payload);
        }
        Some([&b"\n"[..], &payload[..]].concat().into())
    }
}

/// Logs every chunk it receives, and `<end>` when it is flushed. It forwards
/// each chunk unchanged, or with `hold` keeps everything until its flush.
struct Recorder {
    seen: Arc<Mutex<Vec<u8>>>,
    hold: bool,
    held: Vec<u8>,
}

#[async_trait::async_trait]
impl ResponseStreamInspector for Recorder {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        self.seen.lock().unwrap().extend_from_slice(chunk);
        if self.hold {
            self.held.extend_from_slice(chunk);
            return ResponseStreamAction::Forward(Bytes::new());
        }
        ResponseStreamAction::Forward(Bytes::copy_from_slice(chunk))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        self.seen.lock().unwrap().extend_from_slice(b"<end>");
        ResponseStreamAction::Forward(std::mem::take(&mut self.held).into())
    }
}

/// Cuts on the first chunk it receives, without deferring.
struct CutNow;

#[async_trait::async_trait]
impl ResponseStreamInspector for CutNow {
    async fn on_chunk(&mut self, _chunk: &[u8]) -> ResponseStreamAction {
        ResponseStreamAction::Terminate(Some(Bytes::from_static(b"LATER")))
    }
}

fn recorder(hold: bool) -> (Box<dyn ResponseStreamInspector>, Arc<Mutex<Vec<u8>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Recorder {
        seen: Arc::clone(&seen),
        hold,
        held: Vec::new(),
    };
    (Box::new(recorder), seen)
}

fn terminal(action: ResponseStreamAction) -> Option<Bytes> {
    match action {
        ResponseStreamAction::Terminate(final_bytes) => final_bytes,
        ResponseStreamAction::Forward(bytes) => panic!("expected Terminate, got {bytes:?}"),
    }
}

#[tokio::test]
async fn a_deferred_cut_sends_the_cleared_bytes_through_later_inspectors_first() {
    // Later inspectors see the cleared bytes exactly once and are flushed,
    // whether they forward them or hold them, before the payload follows
    // them. The payload starts on a fresh line after bytes that end mid-line.
    let cases: [(&[u8], &[u8]); 2] = [(b"abc!xyz", b"abc\nERR"), (b"ab\n!xyz", b"ab\nERR")];
    for hold in [false, true] {
        for (chunk, expected) in cases {
            let label = format!("hold {hold}, {:?}", String::from_utf8_lossy(chunk));
            let cutter = DeferringCutter::new(b'!', Some(b"ERR"));
            let (later, seen) = recorder(hold);
            let mut chain =
                chain_response_stream_inspectors(vec![Box::new(cutter), later]).expect("chain");
            let final_bytes = terminal(chain.on_chunk(chunk).await);
            assert_eq!(final_bytes.as_deref(), Some(expected), "{label}");
            let released = &chunk[..chunk.len() - 4];
            let expected_seen = [released, &b"<end>"[..]].concat();
            assert_eq!(*seen.lock().unwrap(), expected_seen, "{label}");
        }
    }
}

#[tokio::test]
async fn a_deferred_silent_cut_sends_only_the_cleared_bytes() {
    let cutter = DeferringCutter::new(b'!', None);
    let (later, _seen) = recorder(true);
    let mut chain = chain_response_stream_inspectors(vec![Box::new(cutter), later]).expect("chain");
    let final_bytes = terminal(chain.on_chunk(b"abc!xyz").await);
    assert_eq!(final_bytes.as_deref(), Some(&b"abc"[..]));

    // Nothing cleared and no payload: the stream just ends.
    let cutter = DeferringCutter::new(b'!', None);
    let (later, _seen) = recorder(false);
    let mut chain = chain_response_stream_inspectors(vec![Box::new(cutter), later]).expect("chain");
    assert_eq!(terminal(chain.on_chunk(b"!xyz").await), None);
}

#[tokio::test]
async fn a_deferred_cut_frames_its_payload_after_what_the_client_already_holds() {
    // The cut clears nothing, so the payload follows the bytes an earlier
    // call sent, which end mid-line.
    let cutter = DeferringCutter::new(b'!', Some(b"ERR"));
    let (later, _seen) = recorder(false);
    let mut chain = chain_response_stream_inspectors(vec![Box::new(cutter), later]).expect("chain");
    let ResponseStreamAction::Forward(sent) = chain.on_chunk(b"ab").await else {
        panic!("no cut yet");
    };
    assert_eq!(sent.as_ref(), b"ab");
    let final_bytes = terminal(chain.on_chunk(b"!xyz").await);
    assert_eq!(final_bytes.as_deref(), Some(&b"\nERR"[..]));
}

#[tokio::test]
async fn a_later_cut_on_the_cleared_bytes_wins() {
    // A later inspector that cuts outright.
    let cutter = DeferringCutter::new(b'!', Some(b"ERR"));
    let later: Box<dyn ResponseStreamInspector> = Box::new(CutNow);
    let mut chain = chain_response_stream_inspectors(vec![Box::new(cutter), later]).expect("chain");
    let final_bytes = terminal(chain.on_chunk(b"abc!xyz").await);
    assert_eq!(final_bytes.as_deref(), Some(&b"LATER"[..]));

    // A later inspector that defers its own cut on the cleared bytes: only
    // what it cleared passes the last inspector, then its payload follows.
    let first = DeferringCutter::new(b'!', Some(b"FIRST"));
    let second = DeferringCutter::new(b'?', Some(b"SECOND"));
    let (last, seen) = recorder(false);
    let inspectors: Vec<Box<dyn ResponseStreamInspector>> =
        vec![Box::new(first), Box::new(second), last];
    let mut chain = chain_response_stream_inspectors(inspectors).expect("chain");
    let final_bytes = terminal(chain.on_chunk(b"a?b!c").await);
    assert_eq!(final_bytes.as_deref(), Some(&b"a\nSECOND"[..]));
    assert_eq!(*seen.lock().unwrap(), b"a<end>");
}

#[tokio::test]
async fn a_cut_deferred_at_the_end_of_the_stream_passes_later_inspectors_first() {
    // The cutter holds until its flush, then clears the bytes before its
    // trigger and defers the cut.
    for hold in [false, true] {
        let cutter = DeferringCutter::holding(b'!', Some(b"ERR\n"));
        let (later, seen) = recorder(hold);
        let mut chain =
            chain_response_stream_inspectors(vec![Box::new(cutter), later]).expect("chain");
        let ResponseStreamAction::Forward(held) = chain.on_chunk(b"abc\n!xyz").await else {
            panic!("hold {hold}: the cutter holds until its flush");
        };
        assert!(held.is_empty(), "hold {hold}");
        let final_bytes = terminal(chain.on_end().await);
        assert_eq!(
            final_bytes.as_deref(),
            Some(&b"abc\nERR\n"[..]),
            "hold {hold}"
        );
        assert_eq!(*seen.lock().unwrap(), b"abc\n<end>", "hold {hold}");
    }
}
