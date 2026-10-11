# 🚀 Deploying SOC CHESS to Render (render.com)

This guide walks you through deploying the complete **SOC CHESS** platform online to [Render](https://render.com).

---

## 🌟 Why This Deployment Works Out-of-the-Box

1. **Unified Full-Stack Container**: The React 18 + Vite frontend is pre-built and served directly by the FastAPI async ASGI server on Render's assigned `$PORT`. No CORS or domain-matching issues.
2. **Autonomous Cloud Database**: If an external MySQL instance is not attached, the backend automatically activates an embedded **SQLite engine** (`soc_chess.db`) so all case management, incidents, alerts, and authentication work immediately without setting up a remote database.
3. **Graceful Cloud Telemetry**: When running in a cloud container without host network cards or TShark, the platform gracefully switches to cloud-simulated telemetry mode without UI errors.

---

## 🛠 Option 1: 1-Click Blueprint Deployment (Recommended)

Render provides native **Infrastructure as Code** using the included [`render.yaml`](render.yaml) file.

### Step 1: Push Code to GitHub / GitLab

```bash
cd c:\wamp64\www\soc-chess
git init
git add .
git commit -m "feat: configure SOC CHESS for Render cloud deployment"
git branch -M main
git remote add origin https://github.com/<YOUR-USERNAME>/soc-chess.git
git push -u origin main
```

### Step 2: Deploy on Render

1. Open your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** in the top navigation bar and select **Blueprint**.
3. Connect your GitHub/GitLab repository (`soc-chess`).
4. Render will detect `render.yaml` and display the blueprint configuration:
   - **Service Name**: `soc-chess`
   - **Runtime**: `Docker`
   - **Plan**: `Free`
   - **Auto Deploy**: Enabled
5. Click **Apply**.
6. Render will build the Docker container and provide a live public URL (e.g. `https://soc-chess.onrender.com`).

---

## 🛠 Option 2: Manual Web Service Deployment

If you prefer to configure the Web Service manually via the Render UI:

1. Go to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** $\rightarrow$ **Web Service**.
3. Select **Build and deploy from a Git repository** and connect your repo.
4. Fill in the service settings:
   - **Name**: `soc-chess`
   - **Region**: Choose the closest region (e.g., `Oregon (US West)` or `Frankfurt (EU)`)
   - **Branch**: `main`
   - **Runtime**: **Docker** (Recommended)
     - *Dockerfile Path*: `./Dockerfile`
     - *Docker Context Directory*: `.`
   - *(Alternative: Native Python Runtime)*
     - *Build Command*: `./build.sh`
     - *Start Command*: `./start.sh`
   - **Instance Type**: **Free** (0.1 CPU, 512 MB RAM) or **Starter**

### Environment Variables to Configure in Render Dashboard:

Under **Environment Variables**, add:

| Key | Recommended Value | Purpose |
|---|---|---|
| `APP_NAME` | `SOC_CHESS` | Application identifier |
| `BACKEND_HOST` | `0.0.0.0` | Cloud network binding |
| `AUTH_ENABLED` | `true` | Enables JWT security |
| `JWT_SECRET` | *(Click "Generate" or set 32+ characters)* | Secure signing key |
| `USE_SQLITE` | `true` | Autonomous embedded cloud database |
| `LLM_ENABLED` | `true` | Enables AI Threat Analyst |
| `NVIDIA_API_KEY` | `nvapi-...` *(Your key)* | NVIDIA NIM Threat Analysis |
| `OPENAI_API_KEY` | `sk-...` *(Optional)* | OpenAI Failover |
| `GEMINI_API_KEY` | *(Optional)* | Gemini Failover |

5. Click **Create Web Service**.

---

## 🌐 Verifying Your Live Deployment

Once the build finishes and shows **Live**:

1. Click on the generated Render URL (e.g., `https://soc-chess.onrender.com`).
2. The **SOC CHESS Dashboard** will load.
3. Test the core endpoints:
   - Health check: `https://soc-chess.onrender.com/api/health`
   - Interactive OpenAPI Docs: `https://soc-chess.onrender.com/docs`
   - System Diagnostics: `https://soc-chess.onrender.com/api/system/status`
   - AI Alerts & Telemetry Scanner: `https://soc-chess.onrender.com/ai-alerts`
   - SOC Case Management: `https://soc-chess.onrender.com/soc-cases`

---

## 🔄 Using an External MySQL Database (Optional)

If you have a cloud MySQL database (e.g. from Aiven, Clever Cloud, PlanetScale, or AWS RDS):

Set these variables in the Render service settings:
- `USE_SQLITE`: `false`
- `MYSQL_HOST`: `<your-db-host>`
- `MYSQL_PORT`: `3306`
- `MYSQL_DATABASE`: `soc_chess`
- `MYSQL_USERNAME`: `<your-db-username>`
- `MYSQL_PASSWORD`: `<your-db-password>`

The backend will automatically switch from SQLite to your external MySQL instance on boot.
