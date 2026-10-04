#!/usr/bin/env python3
"""Bounded Linux/WSL2 benchmark for v2, v3 A3/A4, and key-update operations."""

import filecmp
import os
import pathlib
import shutil
import statistics
import subprocess
import tempfile
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = ROOT / "target/release/lvau-cli"
SIZES_MIB = (1, 256)
RUNS = 3


def cli(args):
    result = subprocess.run(
        [str(BINARY), *map(str, args)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(f"fixture setup failed: {args}\n{result.stderr[-2000:]}")


def make_input(path, size_mib):
    remaining = size_mib * 1024 * 1024
    with path.open("wb") as output:
        while remaining:
            block = os.urandom(min(1024 * 1024, remaining))
            output.write(block)
            remaining -= len(block)


def measure(work, size_mib, label, source, output_kind, args_for_output, input_path):
    rows = []
    for run in range(1, RUNS + 1):
        suffix = ".out" if output_kind == "plaintext" else ".lvau"
        output = work / f"measure-{label}-{size_mib}-{run}{suffix}"
        metrics = work / f"measure-{label}-{size_mib}-{run}.time"
        args = args_for_output(output)
        started = time.perf_counter_ns()
        result = subprocess.run(
            [
                "/usr/bin/time",
                "-f",
                "@@METRIC@@%P,%M",
                "-o",
                str(metrics),
                str(BINARY),
                *map(str, args),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wall_s = (time.perf_counter_ns() - started) / 1_000_000_000
        if result.returncode:
            raise RuntimeError(f"{label} failed at {size_mib} MiB, run {run}")
        cpu_pct, max_rss_kib = metrics.read_text().strip().removeprefix("@@METRIC@@").split(",")
        output_bytes = 0
        if output_kind != "verify":
            output_bytes = output.stat().st_size
            if output_kind == "plaintext" and not filecmp.cmp(input_path, output, shallow=False):
                raise RuntimeError(f"{label} roundtrip mismatch at {size_mib} MiB")
            output.unlink()
        rows.append({
            "case": label,
            "size_mib": size_mib,
            "run": run,
            "wall_s": wall_s,
            "cpu_pct": float(cpu_pct.rstrip("%")),
            "max_rss_kib": int(max_rss_kib),
            "output_bytes": output_bytes,
        })
    return rows


def main():
    if not BINARY.is_file():
        raise SystemExit("Build first with: cargo build --locked --workspace --release")
    if shutil.disk_usage("/tmp").free < max(SIZES_MIB) * 1024 * 1024 * 12:
        raise SystemExit("Not enough free /tmp space for the bounded benchmark matrix")

    records = []
    with tempfile.TemporaryDirectory(prefix="lvau-v3-bench-", dir="/tmp") as temp:
        work = pathlib.Path(temp)
        password = work / "old-password.txt"
        new_password = work / "new-password.txt"
        password.write_text("benchmark-only-old-password\n")
        new_password.write_text("benchmark-only-new-password\n")
        password.chmod(0o600)
        new_password.chmod(0o600)
        key1 = work / "key1"
        key2 = work / "key2"
        cli(["keygen", "--out-base", key1])
        cli(["keygen", "--out-base", key2])
        key1_pub = work / "key1.lvau-pub"
        key1_priv = work / "key1.lvau-key"
        key2_pub = work / "key2.lvau-pub"

        for size_mib in SIZES_MIB:
            source = work / f"input-{size_mib}MiB.bin"
            make_input(source, size_mib)
            v2 = work / f"v2-{size_mib}.lvau"
            legacy_v3 = work / f"legacy-v3-{size_mib}.lvau"
            a3 = work / f"a3-{size_mib}.lvau"
            a4 = work / f"a4-mlkem-{size_mib}.lvau"
            a4_password = work / f"a4-password-{size_mib}.lvau"
            a4_mlkem_two = work / f"a4-mlkem-two-{size_mib}.lvau"
            a4_mixed = work / f"a4-mixed-{size_mib}.lvau"

            # Fixture generation is unmeasured. All measured commands use the
            # same random input, release binary, Fast profile, and tmpfs.
            cli(["encrypt", "--password", "--in-file", source, "--out-file", v2, "--password-file", password, "--profile", "fast"])
            cli(["encrypt", "--in-file", source, "--out-file", legacy_v3, "--password-file", password, "--profile", "fast", "--format", "v3", "--suite", "lv3-xc20p"])
            cli(["encrypt", "--in-file", source, "--out-file", a3, "--format", "v3", "--suite", "lv3-xc20p", "--recipient-suite", "x25519-hpke", "--pub-key", key1_pub])
            cli(["encrypt", "--in-file", source, "--out-file", a4, "--format", "v3", "--suite", "lv3-xc20p", "--recipient-suite", "ml-kem-768", "--pub-key", key1_pub])
            cli(["rekey", "change-password", "--in-file", a4, "--out-file", a4_password, "--priv-key", key1_priv, "--new-password-file", password, "--profile", "fast"])
            cli(["rekey", "add-recipient", "--in-file", a4_password, "--out-file", a4_mlkem_two, "--password-file", password, "--pub-key", key2_pub, "--recipient-suite", "ml-kem-768"])
            cli(["rekey", "add-recipient", "--in-file", a4_mlkem_two, "--out-file", a4_mixed, "--password-file", password, "--pub-key", key2_pub, "--recipient-suite", "x25519-hpke"])

            cases = [
                ("v2-encrypt", v2, "capsule", lambda out: ["encrypt", "--password", "--in-file", source, "--out-file", out, "--password-file", password, "--profile", "fast"]),
                ("v2-decrypt", v2, "plaintext", lambda out: ["decrypt", "--in-file", v2, "--out-file", out, "--password-file", password]),
                ("v2-verify", v2, "verify", lambda _: ["verify", "--in-file", v2, "--password-file", password]),
                ("v3-password-encrypt", legacy_v3, "capsule", lambda out: ["encrypt", "--in-file", source, "--out-file", out, "--password-file", password, "--profile", "fast", "--format", "v3", "--suite", "lv3-xc20p"]),
                ("v3-password-decrypt", legacy_v3, "plaintext", lambda out: ["decrypt", "--in-file", legacy_v3, "--out-file", out, "--password-file", password]),
                ("v3-password-verify", legacy_v3, "verify", lambda _: ["verify", "--in-file", legacy_v3, "--password-file", password]),
                ("a3-x25519-encrypt", a3, "capsule", lambda out: ["encrypt", "--in-file", source, "--out-file", out, "--format", "v3", "--suite", "lv3-xc20p", "--recipient-suite", "x25519-hpke", "--pub-key", key1_pub]),
                ("a3-x25519-decrypt", a3, "plaintext", lambda out: ["decrypt", "--in-file", a3, "--out-file", out, "--priv-key", key1_priv]),
                ("a3-x25519-verify", a3, "verify", lambda _: ["verify", "--in-file", a3, "--priv-key", key1_priv]),
                ("a4-mlkem-encrypt", a4, "capsule", lambda out: ["encrypt", "--in-file", source, "--out-file", out, "--format", "v3", "--suite", "lv3-xc20p", "--recipient-suite", "ml-kem-768", "--pub-key", key1_pub]),
                ("a4-mlkem-decrypt", a4, "plaintext", lambda out: ["decrypt", "--in-file", a4, "--out-file", out, "--priv-key", key1_priv]),
                ("a4-mlkem-verify", a4, "verify", lambda _: ["verify", "--in-file", a4, "--priv-key", key1_priv]),
                ("a4-add-mlkem", a4_password, "capsule", lambda out: ["rekey", "add-recipient", "--in-file", a4_password, "--out-file", out, "--password-file", password, "--pub-key", key2_pub, "--recipient-suite", "ml-kem-768"]),
                ("a4-add-x25519", a4_password, "capsule", lambda out: ["rekey", "add-recipient", "--in-file", a4_password, "--out-file", out, "--password-file", password, "--pub-key", key2_pub, "--recipient-suite", "x25519-hpke"]),
                ("a4-remove-mlkem", a4_mlkem_two, "capsule", lambda out: ["rekey", "remove-recipient", "--in-file", a4_mlkem_two, "--out-file", out, "--password-file", password, "--pub-key", key2_pub, "--recipient-suite", "ml-kem-768"]),
                ("a4-remove-x25519", a4_mixed, "capsule", lambda out: ["rekey", "remove-recipient", "--in-file", a4_mixed, "--out-file", out, "--password-file", password, "--pub-key", key2_pub, "--recipient-suite", "x25519-hpke"]),
                ("a4-change-password", a4_password, "capsule", lambda out: ["rekey", "change-password", "--in-file", a4_password, "--out-file", out, "--password-file", password, "--new-password-file", new_password]),
                ("legacy-v3-root-rotate", legacy_v3, "capsule", lambda out: ["rekey", "rotate-root", "--in-file", legacy_v3, "--out-file", out, "--password-file", password, "--new-password-file", new_password, "--profile", "fast"]),
            ]
            for label, fixture, kind, command in cases:
                records.extend(measure(work, size_mib, label, fixture, kind, command, source))
    return records

def report(records):
    print("MEDIANS OF THREE RUNS (wall: perf_counter; CPU/RSS: GNU time)")
    print("case,size_mib,wall_s,cpu_pct,max_rss_kib,throughput_mib_s,output_bytes")
    for size_mib in SIZES_MIB:
        for label in dict.fromkeys(row["case"] for row in records):
            samples = [row for row in records if row["case"] == label and row["size_mib"] == size_mib]
            if not samples:
                continue
            wall = statistics.median(row["wall_s"] for row in samples)
            cpu = statistics.median(row["cpu_pct"] for row in samples)
            rss = statistics.median(row["max_rss_kib"] for row in samples)
            output_bytes = int(statistics.median(row["output_bytes"] for row in samples))
            print(f"{label},{size_mib},{wall:.6f},{cpu:.1f},{rss},{size_mib / wall:.1f},{output_bytes}")
    print("\n256 MiB median wall-time chart (bar scaled to 40 columns)")
    large = []
    for label in dict.fromkeys(row["case"] for row in records):
        samples = [row["wall_s"] for row in records if row["case"] == label and row["size_mib"] == 256]
        if samples:
            large.append((label, statistics.median(samples)))
    maximum = max(value for _, value in large)
    for label, value in large:
        print(f"{label:24} {'#' * max(1, round(40 * value / maximum))} {value:.3f}s")


if __name__ == "__main__":
    report(main())
