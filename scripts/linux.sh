#!/usr/bin/env bash
# Run a command on the pinned Linux, with its memory bounded.
#
# Sourced by the two gates that need Linux; also runnable directly to get a
# shell there:  scripts/linux.sh bash
#
# ---------------------------------------------------------------------------
# What this buys, and why the cap is the point
# ---------------------------------------------------------------------------
#
# A mutation campaign deliberately compiles wrong programs, and a wrong program
# may allocate without bound -- a mutant that reverses a loop counter takes
# whatever the machine has, and takes it in seconds. A timeout is no defence,
# because a timeout bounds TIME rather than memory. An admission queue is no
# defence either, because admission is decided when a job ASKS and never
# resizes one already running.
#
# A cgroup does bound it. Inside `--memory`, the kernel kills the offending
# process and the campaign records the result and continues. The host is never a
# participant. That is the whole reason this file exists, and it is why the
# limit is not a tunable nicety -- running these gates uncapped is the bug.
set -uo pipefail

KEYLESS_IMAGE="${KEYLESS_IMAGE:-keyless-linux-gate}"

# Sized against the DOCKER VM, never the host: off Linux the runtime runs its
# own Linux VM with its own RAM, and a cap above that VM's size is not a cap at
# all -- the VM dies first and takes every container with it.
linux_memory_cap() {
  local vm_bytes
  vm_bytes=$(docker info --format '{{.MemTotal}}' 2>/dev/null) || return 1
  [ -n "$vm_bytes" ] && [ "$vm_bytes" -gt 0 ] 2>/dev/null || return 1
  # Half the VM, floored at 2 GB and capped at 8 GB. Half so a second container
  # (or the VM itself) still has room; 8 GB because no honest test in this suite
  # needs more, and a cap that is never reached teaches nothing.
  local half=$((vm_bytes / 2))
  local cap=$((8 * 1024 * 1024 * 1024))
  [ "$half" -lt "$cap" ] && cap="$half"
  local floor=$((2 * 1024 * 1024 * 1024))
  [ "$cap" -lt "$floor" ] && cap="$floor"
  echo "$cap"
}

linux_available() {
  command -v docker > /dev/null 2>&1 || return 1
  docker info > /dev/null 2>&1 || return 1
}

# Build if absent. Cheap when the layers are cached, and it means no separate
# "set it up first" step anyone can forget.
linux_image_ready() {
  if docker image inspect "$KEYLESS_IMAGE" > /dev/null 2>&1; then
    return 0
  fi
  echo "building $KEYLESS_IMAGE (first run only)..." >&2
  docker build \
    --build-arg "UID=$(id -u)" \
    --build-arg "GID=$(id -g)" \
    -t "$KEYLESS_IMAGE" \
    -f docker/Dockerfile \
    docker
}

# linux_run <name> <command...>
#
# `--memory-swap` equal to `--memory` means NO swap: the kernel kills the
# process at the limit instead of thrashing the VM into uselessness first. A
# swapping container looks like a hung one, and a hung one is what nobody
# notices until the machine is unusable.
linux_run() {
  local name="$1"; shift
  local cap; cap=$(linux_memory_cap) || { echo "cannot size the memory cap; refusing to run uncapped" >&2; return 1; }
  local cpus; cpus=$(docker info --format '{{.NCPU}}' 2>/dev/null || echo 2)
  [ "$cpus" -gt 2 ] 2>/dev/null && cpus=$((cpus - 1)) || cpus=1

  echo "linux: ${cap} bytes memory, ${cpus} cpus, image $KEYLESS_IMAGE" >&2
  docker run --rm \
    --name "$name" \
    --memory "$cap" \
    --memory-swap "$cap" \
    --cpus "$cpus" \
    --volume "$(pwd):/work" \
    --volume "keyless-cargo:/cargo" \
    --volume "keyless-target:/target" \
    --workdir /work \
    "$KEYLESS_IMAGE" \
    "$@"
}

# Direct invocation: hand the arguments straight to the pinned Linux.
#
# `${BASH_SOURCE[0]-}` with the dash, because this file is also SOURCED, and a
# zsh that sources it under `set -u` has no BASH_SOURCE at all -- an unset-
# variable error at the bottom of a library reads as the library being broken.
if [ "${BASH_SOURCE[0]-}" = "${0-}" ] && [ -n "${BASH_SOURCE[0]-}" ]; then
  cd "$(dirname "${BASH_SOURCE[0]}")/.."
  if ! linux_available; then
    echo "no docker daemon is answering, so there is no Linux to run on." >&2
    echo "Start a container runtime, or run this on a Linux host directly." >&2
    exit 1
  fi
  linux_image_ready || exit 1
  linux_run "keyless-linux-$$" "${@:-bash}"
fi
