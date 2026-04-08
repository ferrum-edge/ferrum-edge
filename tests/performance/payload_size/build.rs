fn main() {
    if let Err(e) = tonic_prost_build::compile_protos("proto/bench.proto") {
        eprintln!("Warning: failed to compile proto/bench.proto: {e}");
        eprintln!("gRPC benchmarks will not be available.");
    }
}
