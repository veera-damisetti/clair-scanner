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
  REGISTRY_PUBLISH_ARGS=(-p 127.0.0.1:5050:5000)
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
# Step 6: Start Clair Combo Container (v4.7.4)
# ---------------------------------------------------------
echo "=== Step 6: Starting Clair Combo (v4.7.4) ==="
# --restart=on-failure:5 lets Clair retry if it starts before Postgres
# finishes accepting connections (important on macOS bridge networking).
"${CONTAINER_ENGINE}" run -d --name clair \
  --restart=on-failure:5 \
  "${NET_ARGS[@]}" \
  "${CLAIR_PUBLISH_ARGS[@]}" \
  -v "${CLAIR_STACK_DIR}/config.yaml:/config/config.yaml:ro,z" \
  --tmpfs /tmp:rw,exec,size=2g \
  -e CLAIR_CONF=/config/config.yaml \
  -e CLAIR_MODE=combo \
  quay.io/projectquay/clair:4.7.4 \
  -conf /config/config.yaml

echo "Waiting for Clair health check (API on :6060)..."
local_clair_ready=false
for i in {1..40}; do
  # Check the API port directly — 8089 can answer even when Clair has crashed.
  if curl -s -f http://127.0.0.1:6060/healthz &>/dev/null || \
     curl -s -f "http://127.0.0.1:6060/indexer/api/v1/index_report/sha256:0000000000000000000000000000000000000000000000000000000000000000" \
       -o /dev/null -w "%{http_code}" 2>/dev/null | grep -qE "^(200|404|400)"; then
    echo "Clair is up and healthy!"
    local_clair_ready=true
    break
  fi
  echo -n "."
  sleep 3
done
echo ""

if [ "${local_clair_ready}" = "false" ]; then
  echo "Error: Clair failed to pass health checks."
  echo "--- Clair logs ---"
  "${CONTAINER_ENGINE}" logs clair --tail 30
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
# Step 7: Start Local Image Registry
# ---------------------------------------------------------
echo "=== Step 7: Starting Local Image Registry ==="
"${CONTAINER_ENGINE}" run -d --name local-registry \
  "${NET_ARGS[@]}" \
  "${REGISTRY_PUBLISH_ARGS[@]}" \
  docker.io/library/registry:2

local_registry_ready=false
for i in {1..10}; do
  if curl -s http://127.0.0.1:5050/v2/ &>/dev/null; then
    echo "Local registry is up on 127.0.0.1:5050!"
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
  "${NORM_S390X}" "docker://127.0.0.1:5050/target-image:s390x" \
  && echo "s390x copy complete." \
  || { echo "ERROR: skopeo copy failed for s390x image. Check auth and network."; exit 1; }

echo "Copying x86_64 image (this may take several minutes for large OCP images)..."
skopeo copy --preserve-digests "${SKOPEO_OPTS_X86[@]}" \
  "${NORM_X86}" "docker://127.0.0.1:5050/target-image:x86_64" \
  && echo "x86_64 copy complete." \
  || { echo "ERROR: skopeo copy failed for x86_64 image. Check auth and network."; exit 1; }

# Confirm tags list
echo "Tags in local registry:"
curl -s http://127.0.0.1:5050/v2/target-image/tags/list

# ---------------------------------------------------------
# Step 9: Inspect images from local registry (no network needed)
# ---------------------------------------------------------
echo "=== Step 9: Inspecting images from local registry ==="
META_S390X="/tmp/clair-meta-s390x-$$.json"
META_X86="/tmp/clair-meta-x86-$$.json"

skopeo inspect --tls-verify=false "docker://127.0.0.1:5050/target-image:s390x" > "${META_S390X}" \
  || { echo "Warning: skopeo inspect failed for s390x; metadata will be unavailable."; echo "{}" > "${META_S390X}"; }
echo "s390x metadata collected."

skopeo inspect --tls-verify=false "docker://127.0.0.1:5050/target-image:x86_64" > "${META_X86}" \
  || { echo "Warning: skopeo inspect failed for x86_64; metadata will be unavailable."; echo "{}" > "${META_X86}"; }
echo "x86_64 metadata collected."

# ---------------------------------------------------------
# Step 10: Scan both images with clairctl
# ---------------------------------------------------------
echo "=== Step 10: Scanning images with clairctl ==="
REPORT_S390X="/tmp/clair-report-s390x-$$.json"
REPORT_X86="/tmp/clair-report-x86-$$.json"

echo "Scanning s390x image..."
"${CLAIRCTL_BIN}" report \
  --host http://127.0.0.1:6060/ \
  --out json \
  127.0.0.1:5050/target-image:s390x \
  > "${REPORT_S390X}" \
  || { echo "Error: clairctl failed to scan s390x image."; exit 1; }
echo "s390x scan finished. Report size: $(wc -c < "${REPORT_S390X}") bytes"

echo "Scanning x86_64 image..."
"${CLAIRCTL_BIN}" report \
  --host http://127.0.0.1:6060/ \
  --out json \
  127.0.0.1:5050/target-image:x86_64 \
  > "${REPORT_X86}" \
  || { echo "Error: clairctl failed to scan x86_64 image."; exit 1; }
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
