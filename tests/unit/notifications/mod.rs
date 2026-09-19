use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
use ferrum_edge::notifications::channels::NotificationChannel;
use serde_json::Value;

mod channels_tests;
mod delivery_tests;
mod dispatch_tests;
mod email_channel_tests;
mod templating_tests;

fn parse_channels(value: &Value) -> Result<HashMap<String, Arc<NotificationChannel>>, String> {
    ferrum_edge::notifications::channels::parse_channels(
        &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Both),
        value,
    )
}
