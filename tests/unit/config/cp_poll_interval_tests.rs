//! Source-pin coverage for CP database poll interval tick behavior.
//!
//! Issue #2985: CP mode must use `MissedTickBehavior::Delay` like database mode
//! so a slow poll cycle cannot enqueue burst catch-up ticks.

#[test]
fn cp_db_poll_interval_uses_missed_tick_delay() {
    let source = include_str!("../../../src/modes/control_plane.rs");
    let poll_start = source
        .find("let db_poll_handle = tokio::spawn(async move {")
        .expect("CP poll task must exist");
    let poll_end = source[poll_start..]
        .find("let mut background_handles = vec![")
        .expect("CP poll task must be collected into background handles");
    let poll_section = &source[poll_start..poll_start + poll_end];

    assert!(
        poll_section.contains("let mut interval = tokio::time::interval(poll_interval);"),
        "CP poll loop must construct a tokio interval from FERRUM_DB_POLL_INTERVAL"
    );
    assert!(
        poll_section
            .contains("interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);"),
        "CP poll interval must Delay missed ticks (not default Burst) to avoid catch-up full polls"
    );

    // Parity pin: database mode is the reference behavior for this setting.
    let database = include_str!("../../../src/modes/database.rs");
    let db_poll_start = database
        .find("let db_poll_handle = tokio::spawn(async move {")
        .expect("database poll task must exist");
    let db_poll_end = database[db_poll_start..]
        .find("background_handles.push(db_poll_handle)")
        .expect("database poll task must be pushed onto background handles");
    let db_poll_section = &database[db_poll_start..db_poll_start + db_poll_end];
    assert!(
        db_poll_section
            .contains("interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);"),
        "database mode must retain Delay missed-tick behavior as the CP parity reference"
    );
}
