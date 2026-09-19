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
    *)
      echo "Unknown option: $1"
      usage
      ;;
  esac
done

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

# ---------------------------------------------------------
# Step 1: Pre-flight & Dependency Checks
# ---------------------------------------------------------
echo "=== Step 1: Pre-flight & Dependency Checks ==="
# Check container engine (support both podman and docker)
CONTAINER_ENGINE=""
if command -v podman &>/dev/null; then
  CONTAINER_ENGINE="podman"
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

# Detect Host Operating System
HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
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
# Step 4: Create Clair Configuration
# ---------------------------------------------------------
echo "=== Step 4: Creating Clair Configuration ==="
cat > "${CLAIR_STACK_DIR}/config.yaml" << 'EOF'
http_listen_addr: "127.0.0.1:6060"
introspection_addr: "127.0.0.1:8089"
log_level: "warn"
indexer:
  connstring: "host=127.0.0.1 port=5432 user=clair dbname=clair sslmode=disable"
  migrations: true
  layer_scan_concurrency: 2
matcher:
  connstring: "host=127.0.0.1 port=5432 user=clair dbname=clair sslmode=disable"
  migrations: true
notifier:
  connstring: "host=127.0.0.1 port=5432 user=clair dbname=clair sslmode=disable"
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
# We create a persistent database volume for postgres to persist vulnerability data across runs.
# This makes subsequent runs instantaneous instead of waiting 3-5 mins!
if ! "${CONTAINER_ENGINE}" volume inspect clair-db-data &>/dev/null; then
  "${CONTAINER_ENGINE}" volume create clair-db-data >/dev/null
  echo "Created persistent volume 'clair-db-data'."
else
  echo "Using existing persistent volume 'clair-db-data'."
fi

"${CONTAINER_ENGINE}" run -d --name clair-db \
  --network=host \
  -v clair-db-data:/var/lib/postgresql/data:z \
  -e POSTGRES_USER=clair \
  -e POSTGRES_DB=clair \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  docker.io/library/postgres:15

echo "Waiting for PostgreSQL to start..."
local_postgres_ready=false
for i in {1..20}; do
  if "${CONTAINER_ENGINE}" exec clair-db psql -U clair -c "SELECT 1;" &>/dev/null; then
    echo "PostgreSQL is ready!"
    local_postgres_ready=true
    break
  fi
  sleep 1.5
done

if [ "${local_postgres_ready}" = "false" ]; then
  echo "Error: PostgreSQL database failed to start."
  exit 1
fi

# ---------------------------------------------------------
# Step 6: Start Clair Combo Container (v4.7.4)
# ---------------------------------------------------------
echo "=== Step 6: Starting Clair Combo (v4.7.4) ==="
"${CONTAINER_ENGINE}" run -d --name clair \
  --network=host \
  -v "${CLAIR_STACK_DIR}/config.yaml:/config/config.yaml:ro,z" \
  --tmpfs /tmp:rw,exec,size=2g \
  -e CLAIR_CONF=/config/config.yaml \
  -e CLAIR_MODE=combo \
  quay.io/projectquay/clair:4.7.4 \
  -conf /config/config.yaml

echo "Waiting for Clair health check..."
local_clair_ready=false
for i in {1..30}; do
  if curl -s -f http://127.0.0.1:8089/healthz &>/dev/null; then
    echo "Clair is up and healthy!"
    local_clair_ready=true
    break
  fi
  echo -n "."
  sleep 2
done
echo ""

if [ "${local_clair_ready}" = "false" ]; then
  echo "Error: Clair failed to pass health checks."
  "${CONTAINER_ENGINE}" logs clair --tail 20
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
  -p 127.0.0.1:5050:5000 \
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

# Build skopeo options — arch is known from the flags, no inspect needed
SKOPEO_OPTS_S390X=("--dest-tls-verify=false" "--override-arch" "s390x")
SKOPEO_OPTS_X86=("--dest-tls-verify=false" "--override-arch" "amd64")

if [ -n "${AUTHFILE}" ] && [ -f "${AUTHFILE}" ]; then
  SKOPEO_OPTS_S390X+=("--authfile" "${AUTHFILE}")
  SKOPEO_OPTS_X86+=("--authfile" "${AUTHFILE}")
fi

echo "Copying s390x image..."
skopeo copy "${SKOPEO_OPTS_S390X[@]}" "${NORM_S390X}" "docker://127.0.0.1:5050/target-image:s390x"
echo "s390x copy complete."

echo "Copying x86_64 image..."
skopeo copy "${SKOPEO_OPTS_X86[@]}" "${NORM_X86}" "docker://127.0.0.1:5050/target-image:x86_64"
echo "x86_64 copy complete."

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
