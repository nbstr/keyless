# The Linux the heavy gates run on, pinned so it is the same Linux every time.
#
# ---------------------------------------------------------------------------
# Why a container rather than "run it on the Mac"
# ---------------------------------------------------------------------------
#
# Two independent reasons, and only one of them is the crash everyone remembers.
#
# 1. THE BASELINE IS LINUX-DERIVED. `.github/mutants-baseline.txt` records the
#    survivors of a campaign that ran `runs-on: ubuntu-latest`. Which mutants
#    survive depends on which tests RUN, and the suite ignores a different set on
#    each platform. A macOS campaign diffed against that file reports differences
#    that are differences of PLATFORM, not of coverage -- a gate that reds for a
#    reason nobody can act on, which is a gate that gets deleted.
#
# 2. ONLY LINUX CAN CAP THE MEMORY. A mutation campaign deliberately builds
#    programs that are wrong, and a wrong program is entitled to allocate
#    forever: measured on 2026-08-22, `replace += with -= in Masker::scan` turned
#    a loop counter around and allocates until something stops it. cargo-mutants' timeout was working correctly and is no
#    defence -- a timeout bounds TIME, and 390 seconds is plenty to exhaust a
#    machine. cgroups bound MEMORY, the OOM killer takes the mutant and nothing
#    else, and the campaign carries on. macOS has no equivalent that holds.
#
# The queue is no defence either, and this file exists partly to correct that
# claim: `cq` decides admission when a job ASKS, and a job already running is not
# made smaller by a cap it already passed.
#
# ---------------------------------------------------------------------------
# Pinning
# ---------------------------------------------------------------------------
#
# By DIGEST, not by tag. `rust:1.98.0-bookworm` is a moving pointer -- the same
# tag gains security patches, and a base that changes under a mutation baseline
# is a baseline that reds on a day nobody touched the code. The tag is kept in
# the comment so a human can see what the digest means.
#
# rust:1.98.0-bookworm as of 2026-08-22
FROM rust@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7

# git: `tests/publication.rs` and `tests/session_coordinate.rs` read the
#      published history and FAIL rather than skip without a repository.
# python3: the hook pack is stdlib-only, so the interpreter is the whole
#      dependency.
# ca-certificates: cargo needs them to reach crates.io on a cold volume.
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
      git=1:2.* \
      python3 \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Pinned exactly. cargo-mutants chooses which mutations to generate, so its
# version is as load-bearing as the compiler's: a newer one can invent a mutant
# the baseline has never seen and red a tree nobody changed.
ARG CARGO_MUTANTS_VERSION=27.1.0
RUN cargo install cargo-mutants --locked --version "${CARGO_MUTANTS_VERSION}"

# A user whose uid matches the caller's, so nothing this container writes into a
# mounted repository comes back owned by root. Docker seeds a fresh named volume
# from the image's own directory ownership, which is why these are created here
# rather than at run time.
ARG UID=1000
ARG GID=1000
# The gid is REUSED when it already exists rather than created. A macOS caller
# is normally uid 501 / gid 20, and gid 20 is `dialout` on Debian -- `groupadd`
# exits 4 on the collision, which reads as a broken Dockerfile rather than as
# the two operating systems numbering their groups differently.
RUN set -eux; \
    if ! getent group "${GID}" > /dev/null; then groupadd --gid "${GID}" builder; fi; \
    group="$(getent group "${GID}" | cut -d: -f1)"; \
    if ! getent passwd "${UID}" > /dev/null; then \
      useradd --uid "${UID}" --gid "${GID}" --create-home builder; \
    fi; \
    user="$(getent passwd "${UID}" | cut -d: -f1)"; \
    mkdir -p /cargo /target /work; \
    chown -R "${UID}:${GID}" /cargo /target /work; \
    echo "container user ${user}:${group} (${UID}:${GID})" 

# A UTF-8 locale, because the product READS one. `Style::decide` picks its
# arrow from LC_ALL/LC_CTYPE/LANG, and a bare Debian sets none of them -- so the
# report renders `->` where `tests/cli.rs` asserts `\u{2192}`, and one end-to-end
# case fails for a reason that is about the image rather than the code. GitHub's
# ubuntu runners set C.UTF-8; this matches them, which is the point.
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    CARGO_HOME=/cargo \
    CARGO_TARGET_DIR=/target \
    CARGO_TERM_COLOR=always \
    RUST_BACKTRACE=1
# The pinned cargo-mutants was installed into root's CARGO_HOME; move it onto a
# PATH the builder user actually has, because CARGO_HOME is about to become an
# empty volume.
RUN cp /usr/local/cargo/bin/cargo-mutants /usr/local/bin/cargo-mutants

# Numeric on purpose: when the uid already existed, the account is Debian's own
# and is not called `builder`.
USER ${UID}:${GID}
WORKDIR /work
