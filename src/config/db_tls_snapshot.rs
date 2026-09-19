//! Pool-owned SQL TLS material. SQLx's Any driver parses the URL again for
//! every new connection, so retaining a pool alone does not retain its trust.
//! Private PEM copies keep both CA and client identity fixed for that pool's
//! entire lifetime, including idle eviction and server-initiated disconnects.

use std::io::{Seek, SeekFrom, Write};
use std::sync::{Arc, OnceLock};

use sqlx::any::AnyPoolOptions;
use tempfile::NamedTempFile;
use tokio::sync::Semaphore;

use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};

/// One snapshot read may stay blocked in the kernel after its async caller's
/// connect timeout drops the receiving future. The permit moves INTO the
/// detached OS thread, so a persistent mount outage admits at most one blocked
/// reader process-wide instead of one per reconnect attempt
/// (`.claude/rules/tls-security.md`: `_FILE`-class reads never run on
/// `spawn_blocking`, whose pool pins runtime teardown).
static SQL_TLS_SNAPSHOT_READ_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn sql_tls_snapshot_read_limit() -> Arc<Semaphore> {
    Arc::clone(SQL_TLS_SNAPSHOT_READ_LIMIT.get_or_init(|| Arc::new(Semaphore::new(1))))
}

/// Zeroing buffer size for the pre-unlink scrub of a private PEM copy.
const SNAPSHOT_SCRUB_CHUNK_BYTES: usize = 4096;

pub struct SqlTlsSnapshot {
    url: String,
    files: Vec<PrivatePemFile>,
}

impl SqlTlsSnapshot {
    /// Snapshot URL-owned and EnvConfig-derived PEM paths alike. No files are
    /// created for SQLite. Errors drop every partially prepared private file.
    pub fn load(db_url: &str, db_type: &str) -> Result<Self, sqlx::Error> {
        if !matches!(db_type, "postgres" | "mysql") {
            return Ok(Self {
                url: db_url.to_string(),
                files: Vec::new(),
            });
        }

        let mut url =
            url::Url::parse(db_url).map_err(|error| sqlx::Error::Configuration(error.into()))?;
        let pairs: Vec<_> = url.query_pairs().into_owned().collect();
        let mut files = Vec::new();
        // Preserve driver precedence for duplicate aliases: only the final
        // value of each material kind is used by the driver and snapshotted.
        let mut selected = std::collections::BTreeMap::new();
        for (index, (key, _)) in pairs.iter().enumerate() {
            if let Some(kind) = material_kind(db_type, key) {
                selected.insert(kind, index);
            }
        }

        if selected.is_empty() {
            return Ok(Self {
                url: db_url.to_string(),
                files,
            });
        }

        url.set_query(None);
        for (index, (key, value)) in pairs.iter().enumerate() {
            let Some(kind) = material_kind(db_type, key) else {
                url.query_pairs_mut().append_pair(key, value);
                continue;
            };
            if selected.get(&kind) != Some(&index) {
                continue;
            }
            let source = CertSource::parse(value, kind);
            let material = load_material_blocking(&source, kind)
                .map_err(|error| sqlx::Error::Configuration(error.into()))?;
            // Own cleanup before the first write: partial writes and failures
            // later in this generation must scrub just like accepted snapshots.
            let mut file = PrivatePemFile {
                file: tempfile::Builder::new()
                    .prefix("ferrum-sql-tls-")
                    .suffix(".pem")
                    .tempfile()?,
            };
            file.file.write_all(material.bytes.expose_secret())?;
            let path = file.file.path().to_str().ok_or_else(|| {
                sqlx::Error::Configuration("SQL TLS snapshot path is not UTF-8".into())
            })?;
            url.query_pairs_mut().append_pair(key, path);
            files.push(file);
        }
        Ok(Self {
            url: url.into(),
            files,
        })
    }

    /// [`Self::load`] on a **detached OS thread**, fenced by a process-wide
    /// one-permit semaphore.
    ///
    /// `load` opens operator-controlled pathnames with blocking `std::fs`, so a
    /// FIFO or stalled NFS mount blocks uninterruptibly. Running it under
    /// `tokio::task::spawn_blocking` would return on schedule when the caller's
    /// connect timeout fires but leave the blocking-pool thread pinned, and
    /// runtime teardown then waits for that pool — the hazard
    /// `.claude/rules/tls-security.md` documents for `_FILE` reads. A detached
    /// thread is owned by no runtime and is never joined, and because the
    /// permit moves into it, a persistent outage admits at most one blocked
    /// reader no matter how fast the reload watcher retries.
    ///
    /// Dropping the returned future does not interrupt the kernel read; the
    /// snapshot the abandoned thread eventually produces is dropped on the
    /// spot, which unlinks any private file it created.
    pub(crate) async fn load_detached(db_url: &str, db_type: &str) -> Result<Self, sqlx::Error> {
        // SQLite has no TLS reads. Its lazy/offline construction must not wait
        // for an unrelated network database's stalled material reader.
        if !matches!(db_type, "postgres" | "mysql") {
            return Self::load(db_url, db_type);
        }
        let db_url = db_url.to_string();
        let db_type = db_type.to_string();
        let permit = sql_tls_snapshot_read_limit()
            .acquire_owned()
            .await
            .map_err(|_| snapshot_error("SQL TLS snapshot reader unavailable"))?;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let join_handle = std::thread::Builder::new()
            .name("ferrum-sql-tls-snapshot".to_string())
            .spawn(move || {
                // The permit belongs to the blocking read, not to the awaiting
                // future: later attempts stay fenced until this one really
                // exits.
                let _permit = permit;
                let _ = sender.send(Self::load(&db_url, &db_type));
            })
            .map_err(|error| sqlx::Error::Configuration(error.into()))?;

        // Dropping the handle detaches the thread. Never join: a blocked read
        // must not pin shutdown after the caller's timeout.
        drop(join_handle);

        receiver
            .await
            .map_err(|_| snapshot_error("SQL TLS snapshot read produced no result"))?
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// The pool owns its callbacks as long as it can establish connections.
    /// This default-true release hook only pins the private files; it leaves
    /// the existing after_connect session setup and checkout checks intact.
    pub(crate) fn pin(self, options: AnyPoolOptions) -> (AnyPoolOptions, String) {
        let url = self.url().to_string();
        let snapshot = Arc::new(self);
        let options = options.after_release(move |_, _| {
            let _keep_material_alive = &snapshot.files;
            Box::pin(async { Ok(true) })
        });
        (options, url)
    }
}

struct PrivatePemFile {
    file: NamedTempFile,
}

impl Drop for PrivatePemFile {
    /// Overwrite each private PEM copy before `NamedTempFile` unlinks it.
    ///
    /// The loaded material buffer is zeroizing (`tls::source::SecretBytes`).
    /// Scrub this file too: unlink alone leaves its blocks readable until the
    /// filesystem reuses them. Configured inline sources may still be retained
    /// in the caller's source URL. Best effort: a
    /// read-only or already-removed file simply skips, and the unlink still
    /// happens.
    fn drop(&mut self) {
        let handle = self.file.as_file_mut();
        let Ok(metadata) = handle.metadata() else {
            return;
        };
        let mut remaining = metadata.len();
        if remaining == 0 || handle.seek(SeekFrom::Start(0)).is_err() {
            return;
        }
        let zeros = [0u8; SNAPSHOT_SCRUB_CHUNK_BYTES];
        while remaining > 0 {
            let chunk = std::cmp::min(remaining, SNAPSHOT_SCRUB_CHUNK_BYTES as u64) as usize;
            if handle.write_all(&zeros[..chunk]).is_err() {
                break;
            }
            remaining -= chunk as u64;
        }
        let _ = handle.flush();
        let _ = handle.sync_data();
    }
}

fn snapshot_error(message: &'static str) -> sqlx::Error {
    sqlx::Error::Configuration(message.into())
}

fn material_kind(db_type: &str, key: &str) -> Option<MaterialKind> {
    match (db_type, key) {
        ("postgres", "sslrootcert" | "ssl-root-cert" | "ssl-ca")
        | ("mysql", "sslca" | "ssl-ca") => Some(MaterialKind::CaBundle),
        ("postgres" | "mysql", "sslcert" | "ssl-cert") => Some(MaterialKind::Cert),
        ("postgres" | "mysql", "sslkey" | "ssl-key") => Some(MaterialKind::Key),
        _ => None,
    }
}
