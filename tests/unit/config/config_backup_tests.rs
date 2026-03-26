use ferrum_gateway::config::config_backup::load_config_backup;
use std::io::Write;

fn write_tmp_file(content: &str) -> (tempfile::NamedTempFile, String) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(content.as_bytes()).unwrap();
    tmp.flush().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    (tmp, path)
}

#[test]
fn test_load_config_backup_valid_json() {
    let json = r#"{
        "version": "1",
        "proxies": [{
            "id": "proxy-1",
            "name": "test-proxy",
            "listen_path": "/api",
            "backend_host": "localhost",
            "backend_port": 3000,
            "backend_protocol": "http"
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let loaded = load_config_backup(&path);
    assert!(loaded.is_some(), "should load valid JSON backup");
    let loaded = loaded.unwrap();
    assert_eq!(loaded.proxies.len(), 1);
    assert_eq!(loaded.proxies[0].id, "proxy-1");
    assert_eq!(loaded.proxies[0].listen_path, "/api");
    assert_eq!(loaded.proxies[0].backend_host, "localhost");
}

#[test]
fn test_load_config_backup_file_not_found() {
    let result = load_config_backup("/tmp/nonexistent-ferrum-backup-12345.json");
    assert!(result.is_none(), "should return None for missing file");
}

#[test]
fn test_load_config_backup_invalid_json() {
    let (_tmp, path) = write_tmp_file("{ not valid json }}}");
    let result = load_config_backup(&path);
    assert!(result.is_none(), "should return None for invalid JSON");
}

#[test]
fn test_load_config_backup_empty_config() {
    let json = r#"{
        "version": "1",
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let loaded = load_config_backup(&path).unwrap();
    assert!(loaded.proxies.is_empty());
    assert!(loaded.consumers.is_empty());
    assert!(loaded.upstreams.is_empty());
}

#[test]
fn test_load_config_backup_normalizes_stream_proxy_paths() {
    let json = r#"{
        "version": "1",
        "proxies": [{
            "id": "tcp-proxy-1",
            "name": "tcp-test",
            "listen_path": "/ignored",
            "backend_host": "10.0.0.1",
            "backend_port": 5432,
            "backend_protocol": "tcp",
            "listen_port": 9999
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let loaded = load_config_backup(&path).unwrap();
    assert_eq!(
        loaded.proxies[0].listen_path, "__tcp:9999",
        "stream proxy paths should be normalized"
    );
}

#[test]
fn test_load_config_backup_preserves_multiple_resources() {
    let json = r#"{
        "version": "1",
        "proxies": [
            {
                "id": "p1",
                "name": "proxy-one",
                "listen_path": "/one",
                "backend_host": "host1",
                "backend_port": 3000,
                "backend_protocol": "http"
            },
            {
                "id": "p2",
                "name": "proxy-two",
                "listen_path": "/two",
                "backend_host": "host2",
                "backend_port": 3001,
                "backend_protocol": "http"
            }
        ],
        "consumers": [{
            "id": "c1",
            "username": "user1",
            "custom_id": "cust1"
        }],
        "plugin_configs": [],
        "upstreams": [{
            "id": "u1",
            "name": "upstream-1",
            "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
        }]
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let loaded = load_config_backup(&path).unwrap();
    assert_eq!(loaded.proxies.len(), 2);
    assert_eq!(loaded.consumers.len(), 1);
    assert_eq!(loaded.upstreams.len(), 1);
    assert_eq!(loaded.consumers[0].username, "user1");
    assert_eq!(loaded.upstreams[0].name, Some("upstream-1".into()));
}

#[test]
fn test_load_config_backup_empty_file() {
    let (_tmp, path) = write_tmp_file("");
    let result = load_config_backup(&path);
    assert!(result.is_none(), "should return None for empty file");
}
