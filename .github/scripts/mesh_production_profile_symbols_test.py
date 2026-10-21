#!/usr/bin/env python3
"""Offline contracts for symbol identity and bounded selected-file extraction."""
import importlib.util
import io
import hashlib
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("symbol_preflight", Path(__file__).with_name("mesh_production_profile_symbols.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def elf(path, *, symbols=False, code=b"A" * 16, identity=b"12345678", dwp=False):
    data = bytearray(128)
    sections = []

    def add(name, content, kind=1, flags=0, addr=0, entsize=0):
        offset = len(data)
        data.extend(content)
        sections.append([name, kind, flags, addr, offset, len(content), 0, 0, 1, entsize])

    if dwp:
        index = struct.pack("<IIII", 2, 1, 1, 2) + bytes(16 + 8 + 4 + 4 + 4)
        add(".debug_cu_index", index)
        add(".debug_info.dwo", b"info")
        add(".debug_abbrev.dwo", b"abbr")
    else:
        add(".text", code, flags=6, addr=0x400080)
        add(".data", b"DATA1234", flags=3, addr=0x400090)
        add(".note.gnu.build-id", struct.pack("<III", 4, len(identity), 3) + b"GNU\0" + identity,
            kind=7, flags=2, addr=0x400098)
        if symbols:
            add(".symtab", bytes(24) + struct.pack("<IBBHQQ", 0, 2, 0, 1, 0x400080, len(code)), kind=2, entsize=24)
    names = b"\0" + b"".join(s[0].encode() + b"\0" for s in sections) + b".shstrtab\0"
    add(".shstrtab", names, kind=3)
    shoff = len(data)
    data.extend(bytes(64))
    for section in sections:
        section[0] = names.index(section[0].encode() + b"\0")
        data.extend(struct.pack("<IIQQQQIIQQ", *section))
    data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 1 if dwp else 2, 62, 1, 0 if dwp else 0x400080,
                     0 if dwp else 64, shoff, 0, 64, 0 if dwp else 56, 0 if dwp else 1,
                     64, len(sections) + 1, len(sections))
    if not dwp:
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 128, 0x400080, 0x400080, len(code), len(code), 1)
    path.write_bytes(data)


def archive(path, rows):
    with tarfile.open(path, "w:gz") as target:
        for name, content, kind in rows:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(content)
            target.addfile(info, io.BytesIO(content))


class Budget:
    unpacked = members = 0

    @staticmethod
    def deadline():
        return None


class Symbols(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.prod, self.debug, self.dwp = [self.root / n for n in ("production", "debug", "envoy.dwp")]
        elf(self.prod)
        elf(self.debug, symbols=True)
        elf(self.dwp, dwp=True)

    def tearDown(self):
        self.temp.cleanup()

    def verify(self):
        return M.verify_symbols(self.prod, self.debug, self.dwp, minimum_functions=1)

    def test_exact_code_with_added_symbols_passes_without_claiming_sample_coverage(self):
        result = self.verify()
        self.assertTrue(result["function_symbol_setup_verified"])
        self.assertFalse(result["sampled_coverage_verified"])
        self.assertFalse(result["source_line_setup_verified"])
        self.assertEqual(result["defined_function_symbols"], 1)
        self.assertIsNone(result["dwp"]["build_id"])

    def test_same_build_id_different_code_fails(self):
        elf(self.debug, symbols=True, code=b"B" * 16)
        with self.assertRaisesRegex(ValueError, "allocated sections differ"):
            self.verify()

    def test_same_code_different_build_id_fails(self):
        elf(self.debug, symbols=True, identity=b"87654321")
        with self.assertRaisesRegex(ValueError, "build ID mismatch"):
            self.verify()

    def test_missing_symbols_and_insufficient_symbols_fail(self):
        elf(self.debug)
        with self.assertRaisesRegex(ValueError, "symtab"):
            self.verify()
        elf(self.debug, symbols=True)
        with self.assertRaisesRegex(ValueError, "insufficient"):
            M.verify_symbols(self.prod, self.debug, self.dwp)

    def test_missing_or_wrong_dwp_fails(self):
        self.dwp.unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            self.verify()
        elf(self.dwp)
        with self.assertRaisesRegex(ValueError, "relocatable"):
            self.verify()

    def test_truncated_elf_fails(self):
        self.debug.write_bytes(b"bad")
        with self.assertRaises(ValueError):
            self.verify()

    def test_selected_file_bound(self):
        with patch.dict(M.LIMITS, file_bytes=16):
            with self.assertRaisesRegex(ValueError, "oversize"):
                self.verify()


class Extraction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dest, self.scratch = self.root / "production", self.root / "scratch"
        self.dest.mkdir()
        self.scratch.mkdir()
        self.layer = self.root / "layer.gz"

    def tearDown(self):
        self.temp.cleanup()

    def extract(self, rows):
        archive(self.layer, rows)
        M.extract_layer(self.layer, self.dest, self.scratch, Budget())

    def test_only_regular_selected_files_are_extracted(self):
        self.extract([("other", b"ignored", tarfile.REGTYPE),
                      ("usr/local/bin/envoy", b"selected", tarfile.REGTYPE)])
        self.assertEqual((self.dest / "envoy").read_bytes(), b"selected")
        self.assertFalse((self.dest / "other").exists())

    def test_selected_symlink_and_traversal_fail(self):
        for name, kind in [("usr/local/bin/envoy", tarfile.SYMTYPE), ("../escape", tarfile.REGTYPE)]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.extract([(name, b"", kind)])

    def test_parent_symlink_fails(self):
        with self.assertRaisesRegex(ValueError, "parent is a link"):
            self.extract([("usr/local", b"", tarfile.SYMTYPE)])

    def test_layer_whiteout_does_not_erase_new_same_layer_file(self):
        (self.dest / "envoy").write_bytes(b"old")
        self.extract([("usr/local/bin/envoy", b"new", tarfile.REGTYPE),
                      ("usr/local/bin/.wh..wh..opq", b"", tarfile.REGTYPE)])
        self.assertEqual((self.dest / "envoy").read_bytes(), b"new")

    def test_whiteout_removes_previous_artifact(self):
        (self.dest / "envoy").write_bytes(b"old")
        self.extract([("usr/local/bin/.wh.envoy", b"", tarfile.REGTYPE)])
        self.assertFalse((self.dest / "envoy").exists())

    def test_retained_and_expansion_limits_fail(self):
        with patch.dict(M.LIMITS, retained_bytes=2):
            with self.assertRaisesRegex(ValueError, "retained"):
                self.extract([("usr/local/bin/envoy", b"big", tarfile.REGTYPE)])
        with patch.dict(M.LIMITS, unpacked_bytes=100):
            with self.assertRaisesRegex(ValueError, "unpacked"):
                self.extract([("usr/local/bin/envoy", b"big", tarfile.REGTYPE)])

    def test_duplicate_selected_members_fail(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.extract([("usr/local/bin/envoy", b"one", tarfile.REGTYPE),
                          ("usr/local/bin/envoy", b"two", tarfile.REGTYPE)])



class RegistryContracts(unittest.TestCase):
    def test_actual_published_debug_manifest_is_pinned_before_any_transfer(self):
        self.assertEqual(M.REPOSITORY, "envoyproxy/envoy")
        self.assertEqual(M.DEBUG_TAG, "debug-v1.39.1")
        self.assertEqual(M.DEBUG, "sha256:e92b495e77ea757aefaa946773b999e1ad92f9f15215e139232e39d7697388ce")
        self.assertEqual(M.IMAGE_REFERENCES, (("production", M.PRODUCTION), ("debug", M.DEBUG)))
        registry = M.Registry.__new__(M.Registry)
        registry.small = lambda url: self.fail("mutable tag reached registry")
        for reference in (M.DEBUG_TAG, "v1.39.1-debug", "v1.39.1"):
            with self.subTest(reference=reference), self.assertRaisesRegex(ValueError, "pinned digest"):
                registry.manifest(reference)

    def test_resolved_manifest_is_pinned_and_exact_original_bytes_retained(self):
        config = b'{"architecture": "amd64", "os": "linux"}'
        config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
        body = json.dumps({"schemaVersion": 2, "config": {"digest": config_digest}, "layers": [{
            "size": 10, "digest": "sha256:" + "1" * 64,
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}]}, indent=3).encode()
        registry = M.Registry.__new__(M.Registry)
        registry.small = lambda url: config if "/blobs/" in url else body
        with tempfile.TemporaryDirectory() as temp:
            result = registry.resolve("sha256:" + hashlib.sha256(body).hexdigest(), Path(temp))
            self.assertEqual(result["platform_digest"], "sha256:" + hashlib.sha256(body).hexdigest())
            self.assertEqual((Path(temp) / "manifest-platform.json").read_bytes(), body)
            self.assertEqual((Path(temp) / "manifest-root.json").read_bytes(), body)

    def test_manifest_digest_mismatch_and_transfer_budget_fail_before_download(self):
        registry = M.Registry.__new__(M.Registry)
        registry.small = lambda url: b"{}"
        with self.assertRaisesRegex(ValueError, "manifest digest mismatch"):
            registry.manifest("sha256:" + "0" * 64)
        registry.transfer = M.LIMITS["transfer_bytes"]
        with self.assertRaisesRegex(ValueError, "transfer bound"):
            registry.download({"size": 1}, Path("never-opened"))

    def test_download_requires_exact_length_and_digest(self):
        body = b"bounded layer"
        descriptor = {"size": len(body), "digest": "sha256:" + hashlib.sha256(body).hexdigest()}
        for content, length, valid in [(body, len(body), True), (body + b"extra", len(body), False),
                                        (b"X" * len(body), len(body), False), (body, None, False)]:
            with self.subTest(length=length, content=content), tempfile.TemporaryDirectory() as temp:
                registry = M.Registry.__new__(M.Registry)
                registry.transfer = 0
                registry.deadline = lambda: None
                response = io.BytesIO(content)
                response.headers = {} if length is None else {"Content-Length": str(length)}
                registry.open = lambda url: response
                target = Path(temp) / "blob"
                if valid:
                    registry.download(descriptor, target)
                    self.assertEqual(target.read_bytes(), body)
                else:
                    with self.assertRaises(ValueError):
                        registry.download(descriptor, target)

    def test_redirect_strips_authorization_and_refuses_http(self):
        request = M.urllib.request.Request("https://registry-1.docker.io/x", headers={"Authorization": "Bearer test"})
        redirect = M.SafeRedirect()
        follow = redirect.redirect_request(request, None, 302, "found", {}, "https://cdn.example/x")
        self.assertIsNone(follow.get_header("Authorization"))
        with self.assertRaisesRegex(ValueError, "non-HTTPS"):
            redirect.redirect_request(request, None, 302, "found", {}, "http://cdn.example/x")


if __name__ == "__main__":
    unittest.main()
