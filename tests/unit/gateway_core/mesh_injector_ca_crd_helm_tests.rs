//! Static Helm/chart contract coverage for injector webhook CA trust
//! (issue #4433) and the UDPResponseAmplificationPolicy CRD upgrade path
//! (issue #4443). These tests read chart sources and CI assertions; they
//! do not require a local `helm` binary. Hosted CI still runs
//! `helm template` in the `helm-chart` job.

use std::path::PathBuf;

fn chart_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("charts/ferrum-mesh")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_chart(rel: &str) -> String {
    std::fs::read_to_string(chart_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read charts/ferrum-mesh/{rel}: {e}");
    })
}

fn read_repo(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read {rel}: {e}");
    })
}

#[test]
fn injector_defaults_disabled_fail_closed_with_empty_ca() {
    let values = read_chart("values.yaml");
    assert!(
        values.contains("enabled: false"),
        "injector must default off"
    );
    assert!(
        values.contains("failurePolicy: Fail"),
        "enabled injector must stay fail-closed"
    );
    assert!(
        values.contains("caBundle: \"\""),
        "caBundle must default empty so render fails until a trust source is set"
    );
    assert!(
        values.contains("injectCaFrom: \"\""),
        "cert-manager injection must default off"
    );
}

#[test]
fn injector_schema_declares_ca_bundle_and_cert_manager() {
    let schema = read_chart("values.schema.json");
    assert!(schema.contains("\"caBundle\""));
    assert!(schema.contains("\"certManager\""));
    assert!(schema.contains("\"injectCaFrom\""));
    assert!(
        schema.contains("cert-manager.io/inject-ca-from"),
        "schema must name the cert-manager annotation"
    );
}

#[test]
fn injector_template_requires_exactly_one_trust_source() {
    let template = read_chart("templates/injector-deployment.yaml");
    let helpers = read_chart("templates/_helpers.tpl");
    assert!(
        helpers.contains("define \"ferrum-mesh.validateInjectorTrust\""),
        "injector trust helper must exist"
    );
    assert!(
        template.contains("include \"ferrum-mesh.validateInjectorTrust\""),
        "--show-only templates/injector-deployment.yaml must still fail without a CA"
    );
    assert!(
        helpers.contains("injector.enabled=true requires injector.caBundle"),
        "fail message must name injector.caBundle"
    );
    assert!(
        helpers.contains("injector.certManager.injectCaFrom"),
        "fail message must name injector.certManager.injectCaFrom"
    );
    assert!(
        helpers.contains("exactly one trust source"),
        "conflicting trust modes must fail"
    );
    assert!(
        helpers.contains("BEGIN CERTIFICATE"),
        "malformed caBundle must be rejected as non-PEM"
    );
    assert!(
        helpers.contains("Do not set failurePolicy to Ignore to bypass this."),
        "fail message must refuse a silent Ignore downgrade"
    );
    assert!(
        template.contains("failurePolicy: {{ .Values.injector.failurePolicy }}"),
        "failurePolicy must stay operator-controlled"
    );
    assert!(
        !template.contains("failurePolicy: Ignore"),
        "template must not hard-code Ignore"
    );
    assert!(
        template.contains("cert-manager.io/inject-ca-from:"),
        "cert-manager annotation path must be rendered when injectCaFrom is set"
    );
    assert!(
        template.contains("{{- if $injectorCa }}"),
        "caBundle must still be omitted unless that trust source is selected"
    );
}

#[test]
fn validation_yaml_runs_injector_trust_on_full_render() {
    let validation = read_chart("templates/validation.yaml");
    assert!(
        validation.contains("include \"ferrum-mesh.validateInjectorTrust\""),
        "full-chart helm template must fail an enabled injector without a CA"
    );
}

#[test]
fn udp_policy_crd_lives_in_templates_not_install_once_crds() {
    let crd_dir = chart_root().join("crds");
    let yaml_left: Vec<_> = std::fs::read_dir(&crd_dir)
        .unwrap_or_else(|e| panic!("read charts/ferrum-mesh/crds: {e}"))
        .filter_map(|entry| {
            let name = entry.ok()?.file_name();
            let name = name.to_string_lossy();
            let is_yaml = name.ends_with(".yaml") || name.ends_with(".yml");
            is_yaml.then(|| name.into_owned())
        })
        .collect();
    assert!(
        yaml_left.is_empty(),
        "Helm crds/ must not ship this CRD YAML (install-once); leftover: {yaml_left:?}"
    );
    let template = read_chart("templates/crds-udpresponseamplificationpolicy.yaml");
    assert!(template.contains("kind: CustomResourceDefinition"));
    assert!(template.contains("udpresponseamplificationpolicies.gateway.ferrum.io"));
    assert!(template.contains("kind: UDPResponseAmplificationPolicy"));
    assert!(
        template.contains("gateway.ferrum.io/crd-schema-version:"),
        "CRD must stamp a schema marker operators can compare to the chart"
    );
    assert!(template.contains("v1alpha1-1"));
    assert!(
        template.contains("helm.sh/resource-policy: keep"),
        "uninstall must not cascade-delete UDPResponseAmplificationPolicy objects"
    );
    assert!(
        template.contains("lookup \"apiextensions.k8s.io/v1\" \"CustomResourceDefinition\""),
        "co-resident releases must skip a CRD owned by another release"
    );
    assert!(
        template.contains("crds.adoptExisting=true"),
        "unmanaged CRDs from the former crds/ directory must fail with an adoption action"
    );
}

#[test]
fn crd_values_and_schema_expose_install_and_schema_version() {
    let values = read_chart("values.yaml");
    assert!(values.contains("crds:"));
    assert!(values.contains("install: true"));
    assert!(values.contains("skipInstallAcknowledged: false"));
    assert!(values.contains("adoptExisting: false"));
    assert!(values.contains("schemaVersion: v1alpha1-1"));
    let schema = read_chart("values.schema.json");
    assert!(schema.contains("\"crds\""));
    assert!(schema.contains("\"skipInstallAcknowledged\""));
    assert!(schema.contains("\"adoptExisting\""));
    assert!(schema.contains("\"udpResponseAmplificationPolicy\""));
    assert!(schema.contains("\"const\": \"v1alpha1-1\""));
    let helpers = read_chart("templates/_helpers.tpl");
    assert!(helpers.contains("define \"ferrum-mesh.validateCrds\""));
    assert!(
        helpers.contains("crds.skipInstallAcknowledged"),
        "skipping CRD install must name the acknowledgement value"
    );
}

#[test]
fn helm_ci_asserts_injector_ca_and_crd_upgrade_path() {
    let ci = read_repo(".github/workflows/ci.yml");
    assert!(
        ci.contains("INJECTOR_CA_BUNDLE="),
        "helm-chart job must define a dummy CA for enabled-injector renders"
    );
    assert!(
        ci.contains("Enabled injector rendered without a CA source"),
        "helm-chart job must fail render when the injector has no CA source"
    );
    assert!(
        ci.contains("injector-no-ca.err"),
        "helm-chart job must capture the missing-CA fail message"
    );
    assert!(
        ci.contains("injector-with-ca.yaml"),
        "helm-chart job must render enabled injector with caBundle"
    );
    assert!(
        ci.contains("injector-cert-manager.yaml"),
        "helm-chart job must render the cert-manager inject-ca-from path"
    );
    assert!(
        ci.contains("injector-both-trust.err"),
        "helm-chart job must reject conflicting trust sources"
    );
    assert!(
        ci.contains("crd-skip-unacked.err"),
        "helm-chart job must fail crds.install=false without acknowledgement"
    );
    assert!(
        ci.contains("crd-skip-acked.yaml"),
        "helm-chart job must omit the CRD when skip is acknowledged"
    );
    assert!(
        ci.contains("gateway.ferrum.io/crd-schema-version"),
        "helm-chart job must assert the CRD schema marker on the default render"
    );
}

#[test]
fn docs_name_operator_action_for_crd_adoption_and_injector_ca() {
    let upgrade = read_repo("docs/upgrade_guide.md");
    assert!(
        upgrade.contains("#4443") && upgrade.contains("**Operator action:**"),
        "upgrade guide must tell operators how to adopt the CRD"
    );
    assert!(
        upgrade.contains("--take-ownership") && upgrade.contains("crds.adoptExisting=true"),
        "upgrade guide must name helm --take-ownership and crds.adoptExisting"
    );
    assert!(
        upgrade.contains("#4433") && upgrade.contains("injector.caBundle"),
        "upgrade guide must name the injector CA values"
    );
    let deploy = read_repo("docs/kubernetes_deployment.md");
    assert!(
        deploy.contains("crds.install") && deploy.contains("gateway.ferrum.io/crd-schema-version"),
        "deployment docs must describe the CRD upgrade path and schema marker"
    );
    assert!(
        deploy.contains("injector.certManager.injectCaFrom"),
        "deployment docs must name the cert-manager trust path"
    );
}
