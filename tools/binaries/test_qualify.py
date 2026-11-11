import hashlib
from pathlib import Path
import tempfile
import unittest

from qualify import TARGETS, inventory_entry, verify_settings


def metadata(system="linux", arch="amd64", cgo="0", trimpath="true", baseline="v1"):
    architecture = "GOAMD64" if arch == "amd64" else "GOARM64"
    return "fixture: go1.26.11\n" + "".join(
        f"\tbuild\t{key}={value}\n" for key, value in {
            "GOOS": system, "GOARCH": arch, "CGO_ENABLED": cgo,
            "-trimpath": trimpath, "-buildmode": "exe", architecture: baseline,
        }.items()
    )


class QualificationTests(unittest.TestCase):
    def test_exact_six_target_inventory(self):
        self.assertEqual(set(TARGETS), {(system, arch) for system in ("linux", "windows", "darwin")
                                        for arch in ("amd64", "arm64")})
        self.assertEqual(len(TARGETS), 6)

    def test_metadata_target_cgo_trimpath_and_cpu_are_not_assumed(self):
        self.assertEqual(verify_settings(metadata(), "linux", "amd64")["CGO_ENABLED"], "0")
        self.assertEqual(verify_settings(metadata("darwin", "arm64", baseline="v8.0"), "darwin", "arm64")["GOARM64"], "v8.0")
        for changed in (metadata("windows"), metadata(cgo="1"), metadata(trimpath="false"),
                        metadata(baseline="v3"), metadata() + "\tbuild\tGOOS=linux\n", ""):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                verify_settings(changed, "linux", "amd64")

    def test_digest_and_size_compare_both_outputs_without_executing_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "artifact", Path(directory) / "repeat"
            value = b"public inventory test bytes, not an executable"
            first.write_bytes(value)
            second.write_bytes(value)
            result = inventory_entry(first, second, "windows", "amd64", {}, "cross-compile-only-not-native-qualified")
            self.assertEqual(result["sha256"], hashlib.sha256(value).hexdigest())
            self.assertEqual(result["size"], len(value))
            self.assertNotIn(directory, repr(result))
            second.write_bytes(value + b"changed")
            with self.assertRaises(ValueError):
                inventory_entry(first, second, "windows", "amd64", {}, "cross-compile-only-not-native-qualified")
            first.write_bytes(b"")
            second.write_bytes(b"")
            with self.assertRaises(ValueError):
                inventory_entry(first, second, "windows", "amd64", {}, "cross-compile-only-not-native-qualified")


if __name__ == "__main__":
    unittest.main()
