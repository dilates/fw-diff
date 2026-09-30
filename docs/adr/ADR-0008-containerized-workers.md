# ADR-0008: Containerized workers for untrusted input

**Status:** Accepted · 2026-09-29

## Context

Firmware images are hostile files: parser CVEs in JVM/Ghidra native code exist, unpackers
(squashfs/cpio/tar) have had path-traversal and bomb issues, and researchers absolutely will
feed fw-diff malware samples and attacker-controlled images.

## Decision

The deterministic core runs **in-process** (trusted local analyst workflow, same threat level
as Ghidra desktop), but `fw-diff ci` and explicit `--worker-mode docker` execute all lifting
and unpacking in **containers**: no network, read-only rootfs, dropped capabilities, seccomp
default profile, memory/CPU/pids caps, tmpfs scratch, and the image itself supplied read-only.
Blob handoff via mounted volumes; results are data, not code.

## Consequences

- Local analysts on trusted images keep the fast path (no Docker required).
- CI integrations (where images are untrusted by definition) are safe by default — we select
  container mode automatically there and refuse to run `ci` in-process unless overridden with
  `--i-know-what-im-doing`.
- Resource caps from pipeline-spec §1.2 are enforced twice: in-process (soft, `resource`
  module) and in-container (hard, cgroups). In `ci` mode soft caps are upgraded to the hard
  values.
- Container images pin Ghidra + toolchain digests (reproducible builds; supply-chain section
  of THREAT_MODEL §3.4); images are rebuilt automatically when Ghidra security releases ship.