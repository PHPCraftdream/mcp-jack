"""CI-only development binary inventory; no release or registry publication."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import tarfile
import tempfile


TARGETS = tuple((system, arch) for system in ("linux", "windows", "darwin") for arch in ("amd64", "arm64"))
FLAGS = ("-trimpath", "-buildvcs=false")


def run(args, cwd, *, env=None, stdout=subprocess.PIPE):
    try:
        return subprocess.run(args, cwd=cwd, env=env, stdout=stdout, stderr=subprocess.PIPE,
                              check=True, timeout=240)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        for captured in (error.stdout, error.stderr):
            if captured:
                print(captured.decode(errors="replace"), file=sys.stderr, flush=True)
        raise


def build_settings(text):
    settings = {}
    for line in text.splitlines():
        fields = line.strip().split("\t")
        if len(fields) == 2 and fields[0] == "build" and "=" in fields[1]:
            key, value = fields[1].split("=", 1)
            if key in settings:
                raise ValueError("duplicate build setting")
            settings[key] = value
    return settings


def verify_settings(text, system, arch):
    settings = build_settings(text)
    required = {"GOOS": system, "GOARCH": arch, "CGO_ENABLED": "0", "-trimpath": "true", "-buildmode": "exe"}
    if any(settings.get(key) != value for key, value in required.items()):
        raise ValueError("binary target/CGO/trimpath metadata mismatch")
    baseline = "GOAMD64" if arch == "amd64" else "GOARM64"
    if settings.get(baseline) != ("v1" if arch == "amd64" else "v8.0"):
        raise ValueError("unexpected CPU baseline")
    return {key: settings[key] for key in (*required, baseline)}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory_entry(first, second, system, arch, settings, execution):
    checksum = digest(first)
    if first.stat().st_size == 0 or checksum != digest(second) or first.stat().st_size != second.stat().st_size:
        raise ValueError("independent source/cache builds are not byte-identical")
    return {"file": first.name, "goos": system, "goarch": arch, "sha256": checksum,
            "size": first.stat().st_size, "reproducible_two_builds": True,
            "build_settings": settings, "execution": execution}


def qualify(source, output, expected_sha, feature_sha):
    source = source.resolve(strict=True)
    revision = run(["git", "rev-parse", "HEAD"], source).stdout.decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or revision != expected_sha:
        raise ValueError("checkout revision does not match workflow revision")
    if feature_sha and not re.fullmatch(r"[0-9a-f]{40}", feature_sha):
        raise ValueError("invalid feature revision")
    run(["git", "diff", "--exit-code", "HEAD", "--"], source)
    host = run(["go", "env", "GOHOSTOS", "GOHOSTARCH"], source).stdout.decode().splitlines()
    if len(host) != 2:
        raise ValueError("unknown compiler host")
    compiler = run(["go", "version"], source).stdout.decode().strip()
    # Fresh output: ошибка не заменяет прошлый artifact.
    output.mkdir(parents=False, exist_ok=False)
    entries = []
    with tempfile.TemporaryDirectory(prefix="jack-binary-qualification-") as temporary:
        temporary = Path(temporary)
        archive = temporary / "source.tar"
        with archive.open("xb") as stream:
            run(["git", "archive", "--format=tar", revision], source, stdout=stream)
        copies = []
        for label in ("first", "second"):
            copy = temporary / label
            copy.mkdir()
            with tarfile.open(archive) as tracked:
                tracked.extractall(copy, filter="data")
            copies.append(copy)
        for system, arch in TARGETS:
            name = f"jack-{system}-{arch}" + (".exe" if system == "windows" else "")
            print(f"{name}: qualifying independent source/cache builds", flush=True)
            binaries = []
            for index, copy in enumerate(copies):
                destination = output / name if index == 0 else temporary / ("repeat-" + name)
                environment = os.environ.copy()
                environment.update({"CGO_ENABLED": "0", "GOTOOLCHAIN": "local", "GOOS": system,
                                    "GOARCH": arch, "GOAMD64": "v1", "GOARM64": "v8.0", "GOFLAGS": "",
                                    "GOEXPERIMENT": "", "GOCACHE": str(temporary / f"cache-{index}")})
                run(["go", "mod", "verify"], copy, env=environment)
                run(["go", "build", *FLAGS, "-o", str(destination), "./cmd/jack"], copy, env=environment)
                binaries.append(destination)
            metadata = run(["go", "version", "-m", str(binaries[0])], source).stdout.decode()
            if not metadata.splitlines() or metadata.splitlines()[0].split()[-1] != compiler.split()[2]:
                raise ValueError("embedded compiler version mismatch")
            settings = verify_settings(metadata, system, arch)
            entry = inventory_entry(*binaries, system, arch, settings, "cross-compile-only-not-native-qualified")
            if [system, arch] == host:
                help_result = run([str(binaries[0]), "help"], source)
                if help_result.stdout or b"jack keygen" not in help_result.stderr:
                    raise ValueError("native help smoke failed")
                entry["execution"] = "native-help-smoke-only-lifecycle-qualified-separately"
            entries.append(entry)
            print(f"{entry['file']}: byte-identical independent builds; {entry['execution']}", flush=True)
    manifest = {"schema_version": 1, "checkout_revision": revision, "feature_revision": feature_sha or revision,
                "compiler": compiler, "compiler_host": host, "cgo_enabled": False, "build_flags": list(FLAGS),
                "publication": "development-artifact-only", "artifacts": entries}
    (output / "inventory.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (output / "SHA256SUMS").write_text("".join(f"{entry['sha256']}  {entry['file']}\n" for entry in entries), encoding="ascii")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--feature-sha", default="")
    arguments = parser.parse_args()
    qualify(arguments.source, arguments.output.resolve(), arguments.expected_sha, arguments.feature_sha)
