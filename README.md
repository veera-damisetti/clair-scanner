# Clair CVE Diff & Report Generator

This tool packages and automates the **Clair CVE Diff Runbook** into a single, highly configurable, and reusable script. It allows you to scan any two container images using Clair and generate three professionally-formatted PDF reports in your current directory or any specified output directory:

1. **Image A CVE Report (`<label_a>_report.pdf`)** — A detailed list of all vulnerabilities in Image A.
2. **Image B CVE Report (`<label_b>_report.pdf`)** — A detailed list of all vulnerabilities in Image B.
3. **Comparison Diff Report (`diff_report.pdf`)** — An analysis of vulnerabilities exclusive to Image A, exclusive to Image B, and their comparison metrics.

---

## Key Features & Enhancements over Manual Runbook

- **Dynamic Platform Adaptability**: Dynamically detects your host architecture (`s390x`, `x86_64`, `arm64`) and automatically fetches the matching `clairctl` v4.9.0 binary.
- **Automatic Architecture Override**: Inspects image architectures and automatically handles the `--override-arch` argument for `skopeo copy` when copying a foreign architecture image (e.g. scanning an `x86_64` image on `s390x` hardware).
- **Persistent Vulnerability Database**: Implements a persistent Podman storage volume (`clair-db-data`) for the PostgreSQL container. This ensures that the vulnerability database is cached on your host, making subsequent runs **instantaneous** rather than waiting 3–5 minutes for index population!
- **Robust Failure Recovery**: Implements a central Bash `trap` handler. In case of user interrupt (Ctrl+C) or script failure, all container resources (`clair`, `clair-db`, `local-registry`) are automatically stopped and removed cleanly.
- **Professional PDF Layouts**: Generates high-quality PDF files with headers, footers, two-pass dynamic page numbers ("Page X of Y"), and color-coded severity metrics (Critical, High, Medium, Low) using a self-contained local Python virtual environment.

---

## Prerequisites

Ensure you have the following CLI commands installed on your host system:
- `podman` OR `docker` (the script automatically detects and supports both container engines)
- `skopeo`
- `curl`
- `python3`

### macOS Compatibility

This tool is **fully cross-platform** and natively compatible with **macOS** (both Apple Silicon/M-series and Intel architectures):
1. **Native Binaries**: The script dynamically detects macOS (`Darwin`) and automatically downloads the native macOS version of `clairctl` (`clairctl-darwin-arm64` or `clairctl-darwin-amd64`).
2. **Container Engine**: You can use either **Docker Desktop** or **Podman for macOS**.
3. **No Setup Required**: All configurations are handled automatically.

---

## Directory Structure

This tool resides in `clair-scanner/`:
- `run-clair-diff.sh` — The main shell orchestrator.
- `generate_pdf_report.py` — The Python PDF report generator using `reportlab`.
- `README.md` — This usage documentation.

---

## Usage Guide

Run the orchestrator script with the pull specifications of the two images you wish to scan and compare.

```bash
./run-clair-diff.sh [options] <image_a> <image_b>
```

### Options

| Option | Description |
|---|---|
| `-a, --authfile <path>` | Path to your registry authentication/pull secret file (default: checks `~/authfile.json`, then `~/.docker/config.json`). |
| `-la, --label-a <name>` | Label for Image A in reports and filename (default: `s390x`). |
| `-lb, --label-b <name>` | Label for Image B in reports and filename (default: `x86_64`). |
| `-o, --output-dir <path>` | Target directory to output the PDF reports (default: `.`). |
| `-k, --keep-containers` | Keep Postgres, Clair, and Registry containers running when script exits (default: false). |
| `-h, --help` | Show the help message. |

### Running the Script (Example)

```bash
./run-clair-diff.sh \
  -a ~/authfile.json \
  -la s390x \
  -lb x86_64 \
  quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:b8673024151590ea3f42695b823f23a428bb345a86c7b9c1d18b53c \
  quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:fe9b41b6fa15547b45123785f14ca88828c8442a9882334b34da13f0
```

Once execution completes, you will find three PDF reports in your current directory:
- `s390x_report.pdf`
- `x86_64_report.pdf`
- `diff_report.pdf`

---

## Under the Hood: Workflow Steps

1. **Pre-flight Checks**: Verifies required CLI tools are present and determines host and target architectures.
2. **Download `clairctl`**: Downloads the architecture-appropriate `clairctl` binary to `~/clair-stack/clairctl` if not already cached.
3. **Container Cleanup**: Automatically checks for and stops any conflicting container names from prior runs.
4. **Clair Configuration**: Writes standard config with necessary migrations and updater adjustments to avoid typical s390x execution panics.
5. **Database Initialization**: Launches PostgreSQL backed by the `clair-db-data` volume and polls until the vulnerability index has populated (> 200,000 CVEs).
6. **Local Registry**: Starts a local registry helper container on port `5050` to host target images for scanning.
7. **Skopeo Copy**: Copies both images to the local registry, dynamically applying architecture overrides as required.
8. **Clair Scan**: Triggers `clairctl report` for both local registry tags, exporting detailed scan metrics to JSON.
9. **PDF Generation**: Sets up a local virtual environment (`.venv`), installs `reportlab`, and executes `generate_pdf_report.py` to parse, diff, and write the beautiful PDF reports.
10. **Cleanup**: Stops and removes the temporary containers and scratch files, leaving only the generated PDFs.
