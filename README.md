# 🛡️ PIDS — AI-Powered Network Intrusion Detection System

**Real-time intrusion detection** that sniffs live network traffic, classifies it
with a **two-stage Machine-Learning pipeline** (plus Deep-Learning models), explains
every alert using a **local LLM analyst (Ollama)**, and streams everything to a
**live React dashboard** over WebSockets.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![Django](https://img.shields.io/badge/Django-4.2.7-092E20?logo=django&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)
![ML](https://img.shields.io/badge/ML-XGBoost%20%7C%20LightGBM%20%7C%20Keras-orange)
![License](https://img.shields.io/badge/License-Educational-green)

> ⚠️ **Responsible-use notice:** This is an educational security project. Only run
> detection or any traffic-generation scripts on networks and machines you **own or
> are explicitly authorized to test**.

---

## 🎯 Overview

PIDS monitors network packets in real time and decides whether traffic is **benign**
or part of an **attack**. Instead of a single model, it uses a **two-stage** design
for higher accuracy and lower false alarms, then asks a Large Language Model to turn
each raw alert into a plain-English explanation an analyst can act on.

- 📡 **Live packet capture** with Scapy
- 🧠 **Two-stage ML detection** (fast filter → detailed classifier)
- 🤖 **Deep-learning models** (DNN) for harder cases
- 💬 **LLM-generated alert explanations** via Ollama (runs locally, no cloud)
- 🕳️ **Zero-day / anomaly detection** for unseen attack patterns
- 🔁 **On-the-fly model retraining** from newly labelled traffic
- 📊 **Real-time React dashboard** with WebSocket live updates and 3D visuals
- 📄 **PDF incident reports** generated with ReportLab

---

## 🧩 Detection Pipeline

| Stage | Component | Job |
|-------|-----------|-----|
| 1 | **Stage-1 — XGBoost** | Fast first pass: is this traffic suspicious at all? |
| 2 | **Stage-2 — LightGBM** | Detailed multi-class attack classification |
| 3 | **Deep Learning (Keras DNN)** | Extra accuracy on ambiguous flows |
| 4 | **Zero-Day module** | Flags anomalies that don't match known classes |
| 5 | **LLM Analyst (Ollama)** | Explains the alert in human language + suggests response |

---

## 🛠️ Tech Stack

**Backend**
- Django 4.2.7 + Django REST Framework
- Django Channels + Redis (real-time WebSockets)
- Scapy (packet capture), psutil (system stats)
- scikit-learn, XGBoost, LightGBM (classical ML)
- TensorFlow / Keras, PyTorch + PyTorch-Geometric (deep learning)
- Ollama (local LLM inference)
- ReportLab (PDF reports), PostgreSQL / SQLite

**Frontend**
- React 18 + React Router
- Material UI (MUI) + Emotion
- Three.js / React-Three-Fiber + Drei (3D visualizations)
- Framer Motion, tsParticles, KaTeX
- Axios (REST), native WebSocket (live feed)

---

## 🏗️ Architecture

```
                 ┌──────────────────────────────┐
   Network ─────▶│  Scapy Sniffer (start_sniffer)│
   packets       └───────────────┬──────────────┘
                                  ▼
                        Feature Extraction
                                  ▼
              Stage-1 (XGBoost) ──▶ Stage-2 (LightGBM) ──▶ DL / Zero-Day
                                  ▼
                           LLM Analyst (Ollama)
                                  ▼
        Django REST API  +  Channels / WebSocket (Redis)
                                  ▼
                    React Dashboard (live alerts, 3D, reports)
```

The detection engine lives in `backend/api/management/commands/pids_core/`
(`feature_extractor`, `ml_engine`, `llm_service`, `traffic_capture`,
`model_retraining`, `report_service`, `stats_manager`, `websocket_manager`).

---

## 📂 Project Structure

```
PIDS_Project/
├── backend/                     # Django + DRF + ML/DL detection engine
│   ├── api/
│   │   ├── management/commands/
│   │   │   ├── start_sniffer.py     # live packet capture entry point
│   │   │   └── pids_core/           # core detection engine modules
│   │   ├── consumers.py / routing.py  # WebSocket real-time feed
│   │   ├── views_*.py               # auth, engine, retraining, zero-day, diagnostics
│   │   └── models.py / serializers.py / urls.py
│   ├── ml_models/               # trained XGBoost + LightGBM models (included)
│   ├── dl_models/               # trained Keras DNN + PyTorch GNN models (included)
│   ├── backend/                 # Django project settings (settings, asgi, wsgi)
│   ├── manage.py
│   └── requirements.txt
│
└── frontend/                    # React dashboard
    ├── public/
    └── src/
        ├── components/  context/  motion/  theme/  utils/
        ├── App.jsx  index.js  config.js
        └── ...
```

> ✅ The trained ML/DL models **are included**, so the project works right after
> cloning. Only `db.sqlite3`, `.env`, and the Python `venv/` are excluded
> (local database / secrets / environment).

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm
- Redis (for WebSockets)
- [Ollama](https://ollama.com) installed and running (for LLM explanations)
- *(Optional)* PostgreSQL — SQLite works out of the box for development

### 1) Backend setup
```bash
# from the project root
python -m venv venv
venv\Scripts\activate          # Windows  (use: source venv/bin/activate on macOS/Linux)

cd backend
pip install -r requirements.txt

# create a .env file in backend/ with your settings, e.g.:
#   SECRET_KEY=your-django-secret-key
#   DEBUG=True

python manage.py makemigrations
python manage.py migrate
python manage.py create_admin    # creates the admin user
python manage.py setup_roles     # sets up user roles
```

### 2) Frontend setup
```bash
cd frontend
npm install
```

### 3) Run it (3 terminals)
```bash
# Terminal 1 — API + WebSocket server
cd backend
python manage.py runserver 0.0.0.0:8000

# Terminal 2 — React dashboard
cd frontend
npm start

# Terminal 3 — live packet sniffer / detection engine
cd backend
python manage.py start_sniffer
```

Then open **http://localhost:3000** in your browser.

---

## 👥 Authors

| Name | Role | Contribution |
|------|------|--------------|
| **Mian Usman** | Lead / Backend & ML | Django backend, two-stage ML + DL detection engine, packet capture, LLM integration, system architecture |
| **Zaryab** | Frontend | React dashboard, UI/UX, real-time visualizations, 3D components |

**Project Type:** Final Year Project (FYP)

---

## 📜 License & Disclaimer

This project is provided for **educational purposes only**. It is intended for
learning about network security and intrusion detection on authorized systems.
The authors are not responsible for any misuse. Third-party libraries retain their
respective licenses.

---

⭐ If you find this project useful, please give it a star!
