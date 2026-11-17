# FL-IDS — Federated Learning for Intrusion Detection System

An end-to-end cybersecurity engineering and research platform combining **Machine Learning**, **Federated Learning (FedAvg)**, **Applied Cryptography (Ed25519, AES-256-GCM, SHA-256)**, and **SOC Network Monitoring**.

> **Runtime Note**: The live web preview server (`server.ts` on port `3000`) executes the full real-time ML training, FedAvg aggregation, Ed25519/AES-256-GCM cryptographic envelope verification, and SQLite persistence (`data/fl_ids.db`) directly in Node.js 22 (`node:crypto` + `node:sqlite`) so the interactive system runs out of the box with zero fabricated metrics. The complete **Python 3.11 + FastAPI + PyTorch + Flower (`flwr`) + scikit-learn + SQLAlchemy + `cryptography`** implementation is also included in `backend/` and `client_simulator/` for Python/Docker deployments.

---

## Core Capabilities

- **Dataset Engineering (`CIC-IDS2017`, `CSE-CIC-IDS2018`, `UNSW-NB15` schemas)**:
  - CSV upload with configurable column mapping, cleaning of `NaN`, `Infinity`, and duplicate rows.
  - Automatic removal of identifier leakage columns (`Flow ID`, `Source IP`, `Destination IP`, `Timestamp`, `Src Port`).
  - Stratified train/val/test split with training-only `StandardScaler` fitting and class-imbalance weighting.
  - Non-IID Dirichlet client partitioning simulating distinct organizations (`Hospital-East`, `FinTech-Core`, `Campus-Net`, `Cloud-Edge`, `Telecom-West`).
- **Machine Learning & Federated Learning**:
  - **Centralized Baselines**: Random Forest (with Gini feature importance), Logistic Regression, and Multi-Layer Perceptron (MLP).
  - **Federated Learning**: Weighted FedAvg across 3–8+ clients, supporting client join/leave, model checkpoints, and optional **DP-SGD** per-sample gradient clipping + Gaussian noise.
- **Cryptographic Security Layer**:
  - **Confidentiality**: TLS transport + **AES-256-GCM** authenticated encryption with unique 96-bit CSPRNG nonces and AAD binding.
  - **Integrity**: Canonical JSON serialization + **SHA-256** digest verification.
  - **Authentication & Anti-Replay**: **Ed25519** digital signatures over `(clientId, round, modelVersion, nonce, payloadSha256)` + coordinator nonce replay registry + key rotation & revocation.
  - **Adversarial Verification**: Built-in coordinator gate tests for payload tampering, replay nonces, unauthorized clients, and weight-norm/NaN poisoning.
- **SOC Dashboard (Dark & Light Modes)**:
  - Overview · Intrusion Detection (CSV upload, binary/multiclass inference, confusion matrix, CSV export) · Federated Learning · Cryptography & Security · Network Monitoring · Model Evaluation.

---

## Quick Start (Web Runtime — Node.js 22)

```bash
# 1. Install Node dependencies
npm install

# 2. Run engine & browser-mode unit tests (ML, FedAvg, Dataset Cleaning, Ed25519/AES-GCM/Replay)
npx --yes tsx --test src/engine/engine.test.ts src/browserEngine/handler.test.ts

# 3. Start full-stack server (Express API + React/Vite SOC Dashboard on port 3000)
npm run dev
```

Open `http://localhost:3000` and sign in using the demo credentials shown on the sign-in page:
- **Admin**: `admin@fl-ids.local` / `Admin@FLIDS2026!`
- **Analyst**: `analyst@fl-ids.local` / `Analyst@FLIDS2026!`

---

## GitHub Pages Deployment (Static Browser Mode)

FL-IDS runs 100% client-side on **GitHub Pages** without sacrificing the core ML, Federated Learning, or Cryptographic architecture. When built in static mode (`VITE_STATIC_MODE=true`), the frontend routes API calls to an in-browser execution engine (`src/browserEngine/`) powered by:
- **Real Machine Learning & Federated Learning**: The exact same TypeScript `dataset.ts` cleaner/Dirichlet non-IID partitioner and `ml.ts` models (Random Forest, Logistic Regression, MLP with optional DP-SGD, and FedAvg aggregation) run directly in the browser.
- **Real Web Crypto API (`crypto.subtle`)**: Ed25519 digital signatures (with automatic ECDSA P-256 fallback if unsupported), AES-256-GCM authenticated encryption with unique 96-bit nonces and AAD binding, canonical SHA-256 digests, and anti-replay protection.
- **Persistent State**: Models, datasets, federated rounds, alerts, client keys, and audit logs persist in `localStorage` across page reloads.

### Automatic Deployment via GitHub Actions
1. Push this repository to GitHub (default branch `main`).
2. In your GitHub repository, open **Settings → Pages** and set **Source** to **GitHub Actions**.
3. The included workflow (`.github/workflows/deploy-pages.yml`) automatically runs unit tests, TypeScript checks, builds `dist/` with `npm run build:pages`, and deploys to `https://<username>.github.io/<repo>/`.

### Manual Local Build & Preview for GitHub Pages
```bash
npm run build:pages
npx vite preview --port 4173
```

---

## Python 3.11 + FastAPI + PyTorch + Flower Setup

### Linux / macOS
```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Generate synthetic CIC-IDS2017 benchmark CSV & provision Ed25519 keys
python scripts/generate_synthetic_data.py --rows 1200
python scripts/provision_keys.py

# Run Python automated tests
pytest -v

# Terminal 1: Start FastAPI backend
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Start Flower SecureFedAvg Server
python -m backend.federated.server --rounds 5 --min-clients 3

# Terminals 3-5: Start 3 independent Federated Clients
python -m client_simulator.client --client-id client-hospital --partition 0 --num-clients 3
python -m client_simulator.client --client-id client-fintech --partition 1 --num-clients 3
python -m client_simulator.client --client-id client-campus --partition 2 --num-clients 3
```

### Windows (PowerShell)
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

python scripts\generate_synthetic_data.py --rows 1200
python scripts\provision_keys.py
pytest -v
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### Docker Compose Deployment
```bash
docker compose up --build
# Optional PostgreSQL profile:
docker compose --profile postgres up --build
```

---

## Real Dataset Preparation (CIC-IDS2017 / UNSW-NB15)

1. Download **CIC-IDS2017** (`MachineLearningCSV.zip` from Canadian Institute for Cybersecurity) or **UNSW-NB15** CSV files into `data/raw/`.
2. Upload any CSV directly on the **Intrusion Detection** page or via `POST /api/datasets/upload`. The pipeline automatically maps common CIC-IDS2017 / UNSW-NB15 column aliases, strips identifier leakage columns (`Flow ID`, `Source IP`, `Destination IP`, `Timestamp`), and removes `NaN`/`Infinity`/duplicate rows.
3. The bundled `data/sample/synthetic_cicids2017_sample.csv` is explicitly marked as **synthetic** and is intended for reproducible testing without large external downloads.

---

## REST API Endpoints

| Method | Endpoint | Auth Role | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Public | Authenticate user & issue HS256 JWT |
| `POST` | `/api/datasets/upload` | Admin, Analyst | Clean & register CSV flow dataset |
| `GET` | `/api/datasets` | Authenticated | List datasets & cleaning reports |
| `POST` | `/api/models/train` | Admin | Train centralized RF / LR / MLP baseline |
| `POST` | `/api/federated/start` | Admin | Launch multi-round FedAvg job |
| `GET` | `/api/federated/status` | Authenticated | Poll active federated job status |
| `GET` | `/api/federated/rounds` | Authenticated | Round-by-round global & client metrics |
| `GET` | `/api/federated/clients` | Authenticated | List clients & latest metrics |
| `POST` | `/api/federated/clients/register` | Admin | Register client & provision Ed25519 key |
| `POST` | `/api/security/keys/:id/rotate` | Admin | Rotate client Ed25519 key pair |
| `POST` | `/api/security/keys/:id/revoke` | Admin | Revoke client public key |
| `POST` | `/api/security/simulate-attack` | Admin, Analyst | Test coordinator crypto rejection gates |
| `POST` | `/api/inference/predict` | Admin, Analyst | Single flow prediction |
| `POST` | `/api/inference/batch` | Admin, Analyst | Batch CSV inference + confusion matrix |
| `GET` | `/api/alerts` | Authenticated | Filterable intrusion alerts |
| `GET` | `/api/metrics` | Authenticated | Centralized vs federated comparison |
| `GET` | `/api/security/audit-logs` | Authenticated | Immutable RBAC & security audit trail |

---

## Documentation Index

See [`docs/architecture_and_methodology.md`](docs/architecture_and_methodology.md) for:
- Mermaid System Architecture, Federated Learning Workflow, and Cryptographic Message Flow diagrams
- 12-Table Database Schema
- Research Methodology, Non-IID & Differential Privacy Trade-offs
- College Major Project Report Outline, Presentation Plan & Viva Questions
