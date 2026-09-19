#!/usr/bin/env bash
#
# Clair CVE Diff Runbook Orchestrator - Any Two Images
# Platform: RHEL 9 on IBM Z (s390x) / Generic Linux
#
# This script orchestrates the scanning and comparison of two container images using Clair,
# producing three PDF reports in your current directory:
#  1. s390x CVE Report     (s390x_report.pdf)
#  2. x86_64 CVE Report    (x86_64_report.pdf)
#  3. Comparison Diff      (diff_report.pdf)
#
# Usage: ./run-clair-diff.sh [options] --s390x <image> --x86 <image>
#

set -euo pipefail

# Default Configuration
IMAGE_S390X=""
IMAGE_X86=""
AUTHFILE=""
OUTPUT_DIR="."
CLAIR_STACK_DIR="${HOME}/clair-stack"
KEEP_CONTAINERS=false

# Print usage instructions
usage() {
  cat << EOF
Clair CVE Diff Runbook Orchestrator — Any Two Images

Usage:
  $0 [options] --s390x <image> --x86 <image>

Required flags:
  --s390x <image>          Pull spec for the s390x image  (e.g. quay.io/repo/img@sha256:...)
  --x86 <image>            Pull spec for the x86_64 image (e.g. quay.io/repo/img@sha256:...)

Options:
  -a, --authfile <path>    Path to registry authfile/pull-secret (defaults to ~/authfile.json or ~/.docker/config.json)
  -o, --output-dir <path>  Output directory for PDF reports (default: current working directory)
  -k, --keep-containers    Keep Postgres, Clair, and Registry containers running after execution (default: false)
  -h, --help               Show this help message

Example:
  $0 \\
    -a ~/authfile.json \\
    --s390x quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:b8673024151590ea3f42695b823f23a428bb345a86c7b9c1d18b53c \\
    --x86   quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:fe9b41b6fa15547b45123785f14ca88828c8442a9882334b34da13f0

EOF
  exit 1
}

# Parse command line options
# Collect any bare positional args for the legacy two-image invocation form
_POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --s390x)
      IMAGE_S390X="$2"
      shift 2
      ;;
    --x86)
      IMAGE_X86="$2"
      shift 2
      ;;
    -a|--authfile)
      AUTHFILE="$2"
      shift 2
      ;;
    -o|--output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -k|--keep-containers)
      KEEP_CONTAINERS=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    -*)
      echo "Unknown option: $1"
      usage
      ;;
    *)
      # bare positional argument — collect for legacy two-image form
      _POSITIONAL_ARGS+=("$1")
      shift
      ;;
  esac
done

# Legacy positional form: <s390x-image> <x86-image>
# Allows: ./run-clair-diff.sh -a authfile <img1> <img2>
if [ -z "${IMAGE_S390X}" ] && [ "${#_POSITIONAL_ARGS[@]}" -ge 1 ]; then
  IMAGE_S390X="${_POSITIONAL_ARGS[0]}"
fi
if [ -z "${IMAGE_X86}" ] && [ "${#_POSITIONAL_ARGS[@]}" -ge 2 ]; then
  IMAGE_X86="${_POSITIONAL_ARGS[1]}"
fi

# Validate required flags
if [ -z "${IMAGE_S390X}" ] || [ -z "${IMAGE_X86}" ]; then
  echo "Error: Both --s390x <image> and --x86 <image> are required."
  usage
fi

# Detect pull secret if not explicitly provided
if [ -z "${AUTHFILE}" ]; then
  if [ -f "${HOME}/authfile.json" ]; then
    AUTHFILE="${HOME}/authfile.json"
  elif [ -f "${HOME}/.docker/config.json" ]; then
    AUTHFILE="${HOME}/.docker/config.json"
  else
    echo "Warning: No registry authfile found at ~/authfile.json or ~/.docker/config.json."
    echo "If your images are private or require pull secrets, please specify --authfile <path>"
  fi
fi

# Resolve output directory to absolute path
mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR=$(cd "${OUTPUT_DIR}" && pwd)
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Detect OS early — needed by container engine selection below
HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')

# ---------------------------------------------------------
# Step 1: Pre-flight & Dependency Checks
# ---------------------------------------------------------
echo "=== Step 1: Pre-flight & Dependency Checks ==="
CONTAINER_ENGINE=""
# On macOS, podman requires a running podman machine (Linux VM).
# Try to ensure the machine is up before committing to podman.
_ensure_podman_machine() {
  # Already reachable — nothing to do
  if podman info &>/dev/null 2>&1; then
    return 0
  fi
  echo "Podman socket not reachable. Attempting to start podman machine..."
  # If no machine exists at all, initialise a default one
  if ! podman machine list --format '{{.Name}}' 2>/dev/null | grep -q .; then
    echo "No podman machine found. Running 'podman machine init' (this may take a few minutes)..."
    podman machine init || return 1
  fi
  podman machine start 2>&1 | grep -v "^$" || true
  # Give the socket a moment to appear
  for i in {1..10}; do
    if podman info &>/dev/null 2>&1; then
      echo "Podman machine is up."
      return 0
    fi
    sleep 2
  done
  echo "Warning: podman machine did not become ready in time."
  return 1
}

if command -v podman &>/dev/null; then
  if [ "${HOST_OS:-$(uname -s | tr '[:upper:]' '[:lower:]')}" = "darwin" ]; then
    if _ensure_podman_machine; then
      CONTAINER_ENGINE="podman"
    elif command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
      echo "Podman machine unavailable; falling back to Docker."
      CONTAINER_ENGINE="docker"
    else
      echo "Error: Podman machine could not start and Docker is not available."
      echo "Run 'podman machine init && podman machine start' manually, then retry."
      exit 1
    fi
  else
    CONTAINER_ENGINE="podman"
  fi
elif command -v docker &>/dev/null; then
  CONTAINER_ENGINE="docker"
else
  echo "Error: Neither podman nor docker is installed. One of them is required."
  exit 1
fi
echo "Container engine detected: ${CONTAINER_ENGINE}"

PREREQS=(skopeo curl python3)
for cmd in "${PREREQS[@]}"; do
  if ! command -v "${cmd}" &>/dev/null; then
    echo "Error: Required command '${cmd}' is not installed."
    exit 1
  fi
done
echo "All system dependencies verified: ${CONTAINER_ENGINE}, skopeo, curl, python3"

# Derive CLAIR_OS from HOST_OS (already set above)
case "${HOST_OS}" in
  darwin) CLAIR_OS="darwin" ;;
  linux) CLAIR_OS="linux" ;;
  *)
    echo "Warning: Unsupported OS '${HOST_OS}'. Defaulting to linux."
    CLAIR_OS="linux"
    ;;
esac

# Detect and normalize host architecture
HOST_ARCH=$(uname -m)
case "${HOST_ARCH}" in
  x86_64) CLAIRCTL_ARCH="amd64" ;;
  s390x) CLAIRCTL_ARCH="s390x" ;;
  aarch64|arm64) CLAIRCTL_ARCH="arm64" ;;
  *)
    echo "Warning: Unknown host architecture ${HOST_ARCH}. Defaulting clairctl to s390x."
    CLAIRCTL_ARCH="s390x"
    ;;
esac

# ---------------------------------------------------------
# Step 2: Download clairctl (cached locally)
# ---------------------------------------------------------
echo "=== Step 2: Set Up Clair Stack Directory & Download clairctl ==="
mkdir -p "${CLAIR_STACK_DIR}"

CLAIRCTL_VERSION="v4.9.0"
CLAIRCTL_BIN="${CLAIR_STACK_DIR}/clairctl"
if [ ! -f "${CLAIRCTL_BIN}" ]; then
  echo "Downloading clairctl ${CLAIRCTL_VERSION} for ${CLAIR_OS}-${CLAIRCTL_ARCH}..."
  CLAIRCTL_URL="https://github.com/quay/clair/releases/download/${CLAIRCTL_VERSION}/clairctl-${CLAIR_OS}-${CLAIRCTL_ARCH}"
  curl -sSL "${CLAIRCTL_URL}" -o "${CLAIRCTL_BIN}"
  chmod +x "${CLAIRCTL_BIN}"
else
  echo "Using cached clairctl binary at ${CLAIRCTL_BIN}"
fi

# Print version
"${CLAIRCTL_BIN}" --version 2>&1 | head -n 1

# ---------------------------------------------------------
# Step 3: Setup Container Cleanup Handler on Interrupt/Exit
# ---------------------------------------------------------
cleanup() {
  if [ "${KEEP_CONTAINERS}" = "true" ]; then
    echo "Skipping container cleanup as requested (--keep-containers)."
    return
  fi
  echo "=== Cleanup: Shutting down containers and freeing resources ==="
  for c in clair clair-db local-registry; do
    if "${CONTAINER_ENGINE}" ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
      echo "Stopping and removing container '${c}'..."
      "${CONTAINER_ENGINE}" stop "${c}" &>/dev/null || true
      "${CONTAINER_ENGINE}" rm "${c}" &>/dev/null || true
    fi
  done
  # Remove the bridge network created for macOS runs
  if [ "${HOST_OS:-}" != "linux" ] && [ -n "${NET_NAME:-}" ]; then
    "${CONTAINER_ENGINE}" network rm "${NET_NAME}" &>/dev/null || true
  fi
  echo "Cleanup complete."
}

# Trap signals to trigger cleanup
trap cleanup EXIT INT TERM

# Stop and remove any preexisting runbook containers to avoid name clashes
for c in clair clair-db local-registry; do
  if "${CONTAINER_ENGINE}" ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
    echo "Cleaning up dangling container from prior run: ${c}..."
    "${CONTAINER_ENGINE}" stop "${c}" &>/dev/null || true
    "${CONTAINER_ENGINE}" rm "${c}" &>/dev/null || true
  fi
done

# ---------------------------------------------------------
# Networking strategy
# On Linux:  --network=host  → containers share host loopback; all services
#            bind/reach each other on 127.0.0.1.
# On macOS:  --network=host is a no-op (containers run in a Linux VM).
#            Use a named bridge network instead; containers reach each other
#            by DNS name (container name), and ports are published to the host.
# ---------------------------------------------------------
if [ "${HOST_OS}" = "linux" ]; then
  DB_HOST="127.0.0.1"
  CLAIR_HTTP_ADDR="127.0.0.1:6060"
  CLAIR_INTRO_ADDR="127.0.0.1:8089"
  NET_ARGS=(--network=host)
  DB_PUBLISH_ARGS=()
  CLAIR_PUBLISH_ARGS=()
  # With --network=host, -p port mappings are silently discarded by podman/docker.
  # The registry container binds directly to the host network on its default port 5000.
  REGISTRY_PUBLISH_ARGS=()
  REGISTRY_PORT=5000
else
  # macOS (and any other non-Linux): named bridge network + explicit port publishes.
  # Containers talk to each other by DNS name; ports are forwarded to the Mac host.
  NET_NAME="clair-net"
  "${CONTAINER_ENGINE}" network inspect "${NET_NAME}" &>/dev/null \
    || "${CONTAINER_ENGINE}" network create "${NET_NAME}" >/dev/null
  DB_HOST="clair-db"
  CLAIR_HTTP_ADDR="0.0.0.0:6060"
  CLAIR_INTRO_ADDR="0.0.0.0:8089"
  NET_ARGS=(--network "${NET_NAME}")
  DB_PUBLISH_ARGS=(-p 127.0.0.1:5432:5432)
  CLAIR_PUBLISH_ARGS=(-p 127.0.0.1:6060:6060 -p 127.0.0.1:8089:8089)
  REGISTRY_PUBLISH_ARGS=(-p 127.0.0.1:5050:5000)
  REGISTRY_PORT=5050
fi

# ---------------------------------------------------------
# Step 4: Create Clair Configuration
# ---------------------------------------------------------
echo "=== Step 4: Creating Clair Configuration ==="
cat > "${CLAIR_STACK_DIR}/config.yaml" << EOF
http_listen_addr: "${CLAIR_HTTP_ADDR}"
introspection_addr: "${CLAIR_INTRO_ADDR}"
log_level: "warn"
indexer:
  connstring: "host=${DB_HOST} port=5432 user=clair dbname=clair sslmode=disable"
  migrations: true
  layer_scan_concurrency: 2
matcher:
  connstring: "host=${DB_HOST} port=5432 user=clair dbname=clair sslmode=disable"
  migrations: true
notifier:
  connstring: "host=${DB_HOST} port=5432 user=clair dbname=clair sslmode=disable"
  migrations: true
updaters:
  sets:
    - rhel
    - ubuntu
    - debian
    - alpine
    - aws
    - suse
    - oracle
    - photon
EOF
echo "Configuration created at ${CLAIR_STACK_DIR}/config.yaml"

# ---------------------------------------------------------
# Step 5: Start PostgreSQL with Host Storage Volume
# ---------------------------------------------------------
echo "=== Step 5: Starting PostgreSQL ==="
# Persistent volume keeps the vuln DB between runs — subsequent runs are instant.
if ! "${CONTAINER_ENGINE}" volume inspect clair-db-data &>/dev/null; then
  "${CONTAINER_ENGINE}" volume create clair-db-data >/dev/null
  echo "Created persistent volume 'clair-db-data'."
else
  echo "Using existing persistent volume 'clair-db-data'."
fi

"${CONTAINER_ENGINE}" run -d --name clair-db \
  "${NET_ARGS[@]}" \
  "${DB_PUBLISH_ARGS[@]}" \
  -v clair-db-data:/var/lib/postgresql/data:z \
  -e POSTGRES_USER=clair \
  -e POSTGRES_DB=clair \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  docker.io/library/postgres:15

echo "Waiting for PostgreSQL to start..."
local_postgres_ready=false
for i in {1..30}; do
  if "${CONTAINER_ENGINE}" exec clair-db psql -U clair -c "SELECT 1;" &>/dev/null; then
    local_postgres_ready=true
    break
  fi
  sleep 1.5
done

if [ "${local_postgres_ready}" = "false" ]; then
  echo "Error: PostgreSQL database failed to start."
  exit 1
fi

# On macOS/bridge, give Postgres a few extra seconds to be fully ready
# for network connections before Clair tries to connect.
if [ "${HOST_OS}" != "linux" ]; then
  echo "Waiting for PostgreSQL network socket to be fully ready..."
  for i in {1..10}; do
    if "${CONTAINER_ENGINE}" exec clair-db \
        psql -U clair -c "SELECT pg_postmaster_start_time();" &>/dev/null; then
      # Also verify it accepts a connection through the bridge network
      if "${CONTAINER_ENGINE}" run --rm \
          "${NET_ARGS[@]}" \
          docker.io/library/postgres:15 \
          psql "postgresql://clair@clair-db/clair?sslmode=disable" \
          -c "SELECT 1;" &>/dev/null; then
        echo "PostgreSQL is ready!"
        break
      fi
    fi
    echo -n "."
    sleep 2
  done
  echo ""
else
  echo "PostgreSQL is ready!"
fi

# ---------------------------------------------------------
# Step 6: Start Local Image Registry (must be up before Clair on macOS)
# ---------------------------------------------------------
# The registry must start before Clair so that on macOS, Clair's container
# can reach it via host.containers.internal:${REGISTRY_PORT} for layer fetching.
echo "=== Step 6: Starting Local Image Registry ==="
"${CONTAINER_ENGINE}" run -d --name local-registry \
  "${NET_ARGS[@]}" \
  "${REGISTRY_PUBLISH_ARGS[@]}" \
  docker.io/library/registry:2

local_registry_ready=false
for i in {1..10}; do
  if curl -s "http://127.0.0.1:${REGISTRY_PORT}/v2/" &>/dev/null; then
    echo "Local registry is up on 127.0.0.1:${REGISTRY_PORT}!"
    local_registry_ready=true
    break
  fi
  sleep 1
done

if [ "${local_registry_ready}" = "false" ]; then
  echo "Error: Local registry failed to start."
  exit 1
fi

# ---------------------------------------------------------
# Step 7: Start Clair Combo Container (v4.7.4)
# ---------------------------------------------------------
echo "=== Step 7: Starting Clair Combo (v4.7.4) ==="

# On macOS (bridge networking), Clair fetches image layers from inside its
# own container. It cannot reach 127.0.0.1:${REGISTRY_PORT} (host-side port).
# --add-host=host.containers.internal:host-gateway maps the host's IP into
# the container so layer URLs can be rewritten to host.containers.internal.
CLAIR_EXTRA_ARGS=()
if [ "${HOST_OS}" != "linux" ]; then
  CLAIR_EXTRA_ARGS+=(--add-host=host.containers.internal:host-gateway)
fi

"${CONTAINER_ENGINE}" run -d --name clair \
  --restart=on-failure:10 \
  "${NET_ARGS[@]}" \
  "${CLAIR_PUBLISH_ARGS[@]}" \
  "${CLAIR_EXTRA_ARGS[@]}" \
  -v "${CLAIR_STACK_DIR}/config.yaml:/config/config.yaml:ro,z" \
  -e CLAIR_MODE=combo \
  quay.io/projectquay/clair:4.7.4 \
  -conf /config/config.yaml

# Health-check: /indexer/api/v1/index_states returns HTTP 200 once Clair's
# indexer is fully initialised and connected to Postgres.
# 8089 (introspection) is NOT used — it always reports OK even when crashed.
# 60 × 5s = 5 minutes total budget.
echo "Waiting for Clair health check (API on :6060)..."
local_clair_ready=false
for i in {1..60}; do
  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    http://127.0.0.1:6060/indexer/api/v1/index_states 2>/dev/null || echo "000")
  if [[ "${http_code}" =~ ^[2345][0-9][0-9]$ ]]; then
    echo "Clair is up and healthy! (HTTP ${http_code})"
    local_clair_ready=true
    break
  fi
  echo -n "."
  sleep 5
done
echo ""

if [ "${local_clair_ready}" = "false" ]; then
  echo "Error: Clair failed to pass health checks after 5 minutes."
  echo "--- Clair logs (last 40 lines) ---"
  "${CONTAINER_ENGINE}" logs clair --tail 40
  echo ""
  echo "Tip: run  ${CONTAINER_ENGINE} logs clair  for full output."
  exit 1
fi

# Poll DB until vulnerability count is > 200,000 (standard load)
echo "Verifying vulnerability database population status (requires > 200,000 records)..."
while true; do
  vuln_count=$("${CONTAINER_ENGINE}" exec clair-db psql -U clair -t -c "SELECT count(*) FROM vuln;" 2>/dev/null | xargs || echo "0")
  if [[ "${vuln_count}" =~ ^[0-9]+$ ]]; then
    echo "Vulnerabilities currently indexed: ${vuln_count}"
    if [ "${vuln_count}" -ge 200000 ]; then
      echo "Vulnerability DB loaded and ready for scanning!"
      break
    fi
  else
    echo "Checking database status..."
  fi
  echo "Database is still populating/updating. This may take 3-5 minutes on the very first run. Retrying in 15s..."
  sleep 15
done

# ---------------------------------------------------------
# Step 8: Skopeo copy images to local registry
# ---------------------------------------------------------
echo "=== Step 8: Copying images to local registry ==="

# Normalize image references (add docker:// prefix if missing)
NORM_S390X="${IMAGE_S390X}"
NORM_X86="${IMAGE_X86}"
[[ ! "${NORM_S390X}" =~ ^docker:// ]] && NORM_S390X="docker://${NORM_S390X}"
[[ ! "${NORM_X86}"   =~ ^docker:// ]] && NORM_X86="docker://${NORM_X86}"

echo "s390x image : ${IMAGE_S390X}"
echo "x86_64 image: ${IMAGE_X86}"

# Build skopeo options — arch is known from the flags, no inspect needed.
# --override-os linux  : required for manifest-list images (OCP ART images are multi-arch)
# --override-arch      : select the correct platform layer from the manifest list
SKOPEO_OPTS_S390X=("--dest-tls-verify=false" "--override-os" "linux" "--override-arch" "s390x")
SKOPEO_OPTS_X86=("--dest-tls-verify=false"   "--override-os" "linux" "--override-arch" "amd64")

if [ -n "${AUTHFILE}" ] && [ -f "${AUTHFILE}" ]; then
  SKOPEO_OPTS_S390X+=("--authfile" "${AUTHFILE}")
  SKOPEO_OPTS_X86+=("--authfile" "${AUTHFILE}")
fi

echo "Copying s390x image (this may take several minutes for large OCP images)..."
skopeo copy --preserve-digests "${SKOPEO_OPTS_S390X[@]}" \
  "${NORM_S390X}" "docker://127.0.0.1:${REGISTRY_PORT}/target-image:s390x" \
  && echo "s390x copy complete." \
  || { echo "ERROR: skopeo copy failed for s390x image. Check auth and network."; exit 1; }

echo "Copying x86_64 image (this may take several minutes for large OCP images)..."
skopeo copy --preserve-digests "${SKOPEO_OPTS_X86[@]}" \
  "${NORM_X86}" "docker://127.0.0.1:${REGISTRY_PORT}/target-image:x86_64" \
  && echo "x86_64 copy complete." \
  || { echo "ERROR: skopeo copy failed for x86_64 image. Check auth and network."; exit 1; }

# Confirm tags list
echo "Tags in local registry:"
curl -s "http://127.0.0.1:${REGISTRY_PORT}/v2/target-image/tags/list"

# ---------------------------------------------------------
# Step 9: Inspect images from local registry (no network needed)
# ---------------------------------------------------------
echo "=== Step 9: Inspecting images from local registry ==="
META_S390X="/tmp/clair-meta-s390x-$$.json"
META_X86="/tmp/clair-meta-x86-$$.json"

skopeo inspect --tls-verify=false "docker://127.0.0.1:${REGISTRY_PORT}/target-image:s390x" > "${META_S390X}" \
  || { echo "Warning: skopeo inspect failed for s390x; metadata will be unavailable."; echo "{}" > "${META_S390X}"; }
echo "s390x metadata collected."

skopeo inspect --tls-verify=false "docker://127.0.0.1:${REGISTRY_PORT}/target-image:x86_64" > "${META_X86}" \
  || { echo "Warning: skopeo inspect failed for x86_64; metadata will be unavailable."; echo "{}" > "${META_X86}"; }
echo "x86_64 metadata collected."

# ---------------------------------------------------------
# Step 10: Scan both images with Clair
# ---------------------------------------------------------
# On Linux (--network=host) clairctl submits 127.0.0.1:${REGISTRY_PORT} directly —
# Clair's indexer shares the host network and fetches layers from the same address.
#
# On macOS (bridge network), Clair's container cannot reach 127.0.0.1:${REGISTRY_PORT}
# (that is a host-side port mapping). We use a two-step approach:
#   1. clairctl manifest builds the manifest JSON (host sees 127.0.0.1:${REGISTRY_PORT} ✓)
#   2. Python rewrites layer URLs: 127.0.0.1:${REGISTRY_PORT} → host.containers.internal:${REGISTRY_PORT}
#      (the Clair container can reach that via --add-host added above)
#   3. POST the rewritten manifest to Clair's indexer REST API directly
#   4. Poll until indexing is complete, then fetch the vuln report
echo "=== Step 10: Scanning images with Clair ==="
REPORT_S390X="/tmp/clair-report-s390x-$$.json"
REPORT_X86="/tmp/clair-report-x86-$$.json"

# Helper: submit one image to Clair and write the vuln report JSON.
# Usage: clair_scan <tag> <report_output_file>
clair_scan() {
  local tag="$1"
  local out="$2"
  local host_ref="127.0.0.1:${REGISTRY_PORT}/target-image:${tag}"
  local clair_api="http://127.0.0.1:6060"

  echo "Building manifest for ${tag}..."
  local manifest_file="/tmp/clair-manifest-${tag}-$$.json"

  if [ "${HOST_OS}" = "linux" ]; then
    # Linux: submit directly via clairctl (network=host, no URL rewrite needed)
    "${CLAIRCTL_BIN}" report \
      --host "${clair_api}/" \
      --out json \
      "${host_ref}" > "${out}" \
      || { echo "Error: clairctl failed to scan ${tag} image."; return 1; }
    return 0
  fi

  # macOS: clairctl manifest → rewrite URLs → POST to indexer → poll → fetch report
  local manifest_err="/tmp/clair-manifest-err-${tag}-$$.txt"
  "${CLAIRCTL_BIN}" manifest "${host_ref}" > "${manifest_file}" 2>"${manifest_err}" || {
    echo "Error: clairctl manifest failed for ${tag}."
    cat "${manifest_err}" >&2
    rm -f "${manifest_err}"
    return 1
  }
  rm -f "${manifest_err}"

  # Validate manifest has content (clairctl exits 0 but writes nothing on some errors)
  if [ ! -s "${manifest_file}" ]; then
    echo "Error: clairctl manifest produced empty output for ${tag}."
    return 1
  fi

  # Rewrite 127.0.0.1:${REGISTRY_PORT} → host.containers.internal:${REGISTRY_PORT}
  # Pass REGISTRY_PORT as an env var since the heredoc uses 'PYEOF' (no expansion inside)
  REGISTRY_PORT="${REGISTRY_PORT}" python3 - "${manifest_file}" << 'PYEOF'
import sys, json, os
path = sys.argv[1]
port = os.environ["REGISTRY_PORT"]
with open(path) as f:
    m = json.load(f)
for layer in m.get("layers", []):
    if "uri" in layer:
        layer["uri"] = layer["uri"].replace(
            f"127.0.0.1:{port}", f"host.containers.internal:{port}"
        )
with open(path, "w") as f:
    json.dump(m, f)
PYEOF

  local layer_count
  layer_count=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1])).get('layers',[])))" \
    "${manifest_file}" 2>/dev/null || echo "?")
  echo "Manifest built: ${layer_count} layer(s)."

  # Extract the manifest digest (the "hash" field)
  local digest
  digest=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['hash'])" \
    "${manifest_file}" 2>/dev/null) \
    || { echo "Error: could not extract manifest digest for ${tag}."; return 1; }
  echo "Submitting manifest ${digest} to Clair indexer..."

  # POST manifest to indexer.
  # HTTP 201 = accepted (indexing starting), HTTP 200 = already indexed (check inline state).
  local post_body="/tmp/clair-post-resp-${tag}-$$.json"
  local http_code
  http_code=$(curl -s -o "${post_body}" -w "%{http_code}" \
    -X POST "${clair_api}/indexer/api/v1/index_report" \
    -H "Content-Type: application/json" \
    --data-binary "@${manifest_file}")

  if [[ ! "${http_code}" =~ ^2 ]]; then
    echo "Error: indexer POST returned HTTP ${http_code} for ${tag}."
    python3 -m json.tool < "${post_body}" 2>/dev/null || cat "${post_body}"
    rm -f "${post_body}" "${manifest_file}"
    return 1
  fi

  # If already indexed (200) and state is already IndexFinished, skip polling
  local inline_state
  inline_state=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('state',''))" \
    "${post_body}" 2>/dev/null || echo "")
  rm -f "${post_body}"

  if [ "${inline_state}" = "IndexFinished" ]; then
    echo "Already indexed (HTTP ${http_code}). Skipping poll."
  else
    echo "Indexing started (HTTP ${http_code}). Waiting for completion (up to 15 min)..."
    # Poll until state == IndexFinished or IndexError
    # 180 × 5s = 15 min — enough for large OCP images (50-100 MB layers via bridge)
    local state=""
    for i in {1..180}; do
      state=$(curl -s "${clair_api}/indexer/api/v1/index_report/${digest}" \
        | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('state',''))" \
        2>/dev/null || echo "")
      echo -n "."
      if [ "${state}" = "IndexFinished" ]; then
        echo ""
        echo "Indexing complete for ${tag}."
        break
      elif [ "${state}" = "IndexError" ]; then
        echo ""
        echo "Error: Clair indexer reported IndexError for ${tag}."
        curl -s "${clair_api}/indexer/api/v1/index_report/${digest}" \
          | python3 -m json.tool 2>/dev/null || true
        return 1
      fi
      sleep 5
    done
    echo ""

    if [ "${state}" != "IndexFinished" ]; then
      echo "Error: Timed out waiting for indexing of ${tag} (last state: '${state}')."
      return 1
    fi
  fi

  # Fetch vulnerability report from matcher
  echo "Fetching vulnerability report for ${tag}..."
  local vuln_resp="/tmp/clair-vuln-resp-${tag}-$$.json"
  http_code=$(curl -s -o "${vuln_resp}" -w "%{http_code}" \
    "${clair_api}/matcher/api/v1/vulnerability_report/${digest}")
  if [[ ! "${http_code}" =~ ^2 ]]; then
    echo "Error: matcher returned HTTP ${http_code} for ${tag}."
    python3 -m json.tool < "${vuln_resp}" 2>/dev/null || cat "${vuln_resp}"
    rm -f "${vuln_resp}"
    return 1
  fi
  mv "${vuln_resp}" "${out}"
  rm -f "${manifest_file}"
}

echo "Scanning s390x image..."
clair_scan "s390x" "${REPORT_S390X}" \
  || { echo "Error: Clair scan failed for s390x image."; exit 1; }
echo "s390x scan finished. Report size: $(wc -c < "${REPORT_S390X}") bytes"

echo "Scanning x86_64 image..."
clair_scan "x86_64" "${REPORT_X86}" \
  || { echo "Error: Clair scan failed for x86_64 image."; exit 1; }
echo "x86_64 scan finished. Report size: $(wc -c < "${REPORT_X86}") bytes"

# ---------------------------------------------------------
# Step 11: Generate PDF Reports
# ---------------------------------------------------------
echo "=== Step 11: Generating PDF Reports ==="

# generate_pdf_report.py uses only Python stdlib — no pip install needed.
echo "Running report generator..."
python3 "${SCRIPT_DIR}/generate_pdf_report.py" \
  --report-a   "${REPORT_S390X}" --label-a  "s390x" \
  --report-b   "${REPORT_X86}"   --label-b  "x86_64" \
  --meta-a     "${META_S390X}" \
  --meta-b     "${META_X86}" \
  --image-a    "${IMAGE_S390X}" \
  --image-b    "${IMAGE_X86}" \
  --output-dir "${OUTPUT_DIR}" \
  || { echo "Error: PDF report generation failed. Check output above for details."; exit 1; }

# Cleanup temp JSON files
rm -f "${REPORT_S390X}" "${REPORT_X86}" "${META_S390X}" "${META_X86}"

echo "========================================================="
echo " Scan and Comparison Complete!"
echo " Reports saved in: ${OUTPUT_DIR}"
echo "   1. s390x CVE Report:    s390x_report.pdf"
echo "   2. x86_64 CVE Report:   x86_64_report.pdf"
echo "   3. Comparison Diff:     diff_report.pdf"
echo "========================================================="
