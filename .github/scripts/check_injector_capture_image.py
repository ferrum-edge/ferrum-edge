#!/usr/bin/env python3
"""Verify injector manifests and errors rendered by the CI-owned Helm executable."""

import argparse
from pathlib import Path

import yaml


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True)
    args = parser.parse_args()
    results = Path(args.results)
    root = Path(__file__).resolve().parents[2]
    chart = root / "charts/ferrum-mesh"
    default_tag = str(yaml.safe_load((chart / "Chart.yaml").read_text())["appVersion"])
    digest = "sha256:" + "a" * 64
    cases = [
        ("default explicit", {}, "ferrumedge/ferrum-edge:" + default_tag),
        ("plain promotion", {"injector.env.FERRUM_MESH_CAPTURE_MODE": "iptables"},
         "ferrumedge/ferrum-edge:" + default_tag + "-ebpf-tools"),
        ("ebpf promotion", {"injector.env.FERRUM_MESH_CAPTURE_MODE": "iptables",
                            "image.tag": "test-ebpf"},
         "ferrumedge/ferrum-edge:test-ebpf-tools"),
        ("tools unchanged", {"injector.env.FERRUM_MESH_CAPTURE_MODE": "iptables",
                             "image.tag": "test-ebpf-tools"},
         "ferrumedge/ferrum-edge:test-ebpf-tools"),
        ("ebpf control", {"injector.env.FERRUM_MESH_CAPTURE_MODE": "ebpf"},
         "ferrumedge/ferrum-edge:" + default_tag),
        ("pinned tools override", {"injector.env.FERRUM_MESH_CAPTURE_MODE": "iptables",
                                  "injector.env.FERRUM_INJECTOR_SIDECAR_IMAGE":
                                  "registry:5000/team/custom:v1-ebpf-tools@" + digest},
         "registry:5000/team/custom:v1-ebpf-tools@" + digest),
        ("explicit custom control", {"injector.env.FERRUM_INJECTOR_SIDECAR_IMAGE":
                                     "registry:5000/team/custom@" + digest},
         "registry:5000/team/custom@" + digest),
        ("plain override refused", {"injector.env.FERRUM_MESH_CAPTURE_MODE": "iptables",
                                   "injector.env.FERRUM_INJECTOR_SIDECAR_IMAGE":
                                   "ferrumedge/ferrum-edge:test"}, None),
        ("bare digest refused", {"injector.env.FERRUM_MESH_CAPTURE_MODE": "iptables",
                                "injector.env.FERRUM_INJECTOR_SIDECAR_IMAGE":
                                "ferrumedge/ferrum-edge@" + digest}, None),
        ("pinned plain refused", {"injector.env.FERRUM_MESH_CAPTURE_MODE": "iptables",
                                 "injector.env.FERRUM_INJECTOR_SIDECAR_IMAGE":
                                 "ferrumedge/ferrum-edge:test@" + digest}, None),
    ]
    for index, (name, overrides, expected) in enumerate(cases):
        returncode = int((results / f"injector-image-{index}.status").read_text())
        stdout = (results / f"injector-image-{index}.out").read_text()
        stderr = (results / f"injector-image-{index}.err").read_text()
        if expected is None:
            assert returncode != 0, f"{name}: render unexpectedly succeeded"
            assert "-ebpf-tools tag" in stderr, f"{name}: {stderr}"
        else:
            assert returncode == 0, f"{name}: {stderr}"
            deployment = next(doc for doc in yaml.safe_load_all(stdout)
                              if doc and doc.get("kind") == "Deployment")
            container = deployment["spec"]["template"]["spec"]["containers"][0]
            images = [item["value"] for item in container["env"]
                      if item["name"] == "FERRUM_INJECTOR_SIDECAR_IMAGE"]
            assert images == [expected], f"{name}: duplicate or wrong sidecar image: {images}"
            tag = overrides.get("image.tag", default_tag)
            assert container["image"] == "ferrumedge/ferrum-edge:" + tag, name
        print("PASS:", name)


if __name__ == "__main__":
    main()
