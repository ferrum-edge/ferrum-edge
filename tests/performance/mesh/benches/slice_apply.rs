//! Bench: `MeshSlice::from_gateway_config(&GatewayConfig, MeshSliceRequest)`
//! over N synthetic workloads + matching MeshService rows. Cold rebuild
//! cost — the ArcSwap swap that follows is constant time and not measured.

use std::collections::HashMap;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshService, ServicePort, Workload, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

fn build_gateway_config(n_workloads: usize) -> GatewayConfig {
    let mut config = GatewayConfig::default();
    let trust_domain =
        TrustDomain::new("cluster.local").expect("static trust-domain must parse");
    let mut mesh = MeshConfig::default();

    for i in 0..n_workloads {
        let uri = format!("spiffe://cluster.local/ns/default/sa/svc-{i}");
        let spiffe_id = SpiffeId::new(&uri).expect("synthetic SPIFFE id must parse");
        let service_name = format!("svc-{i}");

        mesh.workloads.push(Workload {
            spiffe_id: spiffe_id.clone(),
            selector: WorkloadSelector::default(),
            service_name: service_name.clone(),
            addresses: vec![format!("10.0.{}.{}", (i / 254) % 254, (i % 254) + 1)],
            ports: vec![],
            trust_domain: trust_domain.clone(),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        });

        mesh.services.push(MeshService {
            name: service_name,
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: Default::default(),
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef { spiffe_id }],
            protocol_overrides: HashMap::new(),
        });
    }

    config.mesh = Some(Box::new(mesh));
    config
}

fn bench_slice_apply(c: &mut Criterion) {
    let mut group = c.benchmark_group("slice_apply");
    for &size in &[100usize, 1_000, 5_000] {
        let config = build_gateway_config(size);
        let request = MeshSliceRequest {
            node_id: "bench-node".to_string(),
            namespace: "default".to_string(),
            ..Default::default()
        };
        group.bench_with_input(BenchmarkId::new("workloads", size), &size, |b, _| {
            b.iter(|| {
                let slice = MeshSlice::from_gateway_config(
                    black_box(&config),
                    black_box(request.clone()),
                );
                black_box(slice);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_slice_apply);
criterion_main!(benches);
