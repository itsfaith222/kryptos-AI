# Kryptos-AI - Guardian AI security assistant

Kryptos-AI is a powerful, multi-agent security pipeline designed to protect users from phishing, scams, and digital threats in real-time. It combines a Chrome extension for immediate detection, a sophisticated multi-agent backend for deep analysis, and a modern dashboard for comprehensive reporting.

---

## 📁 Project Structure

```text
├── extension/          # Chrome Extension (Manifest V3)
│   ├── popup.js/html   # Tool for manual text/screenshot analysis
│   ├── content.js      # Link hover detection and page scanning
│   └── background.js   # Orchestrator for extension events
├── backend/            # FastAPI Backend
│   ├── agents/         # Multi-agent logic (Scout, Analyst, Educator)
│   ├── main.py         # Orchestrator and WebSocket server
│   ├── contracts.py    # Data models (Pydantic) for agent communication
│   └── .env            # Environment secrets (API Keys, MongoDB)
└── webapp/             # React + Vite Dashboard
    ├── src/            # UI Components and state management
    └── tailwind.config # Modern styling framework
```

---

## 🚀 Quick Start

### 1. Backend Setup
```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate    # Windows
source venv/bin/activate   # Mac/Linux
pip install -r requirements.txt
```
*   Create a `.env` file in `/backend` with:
    `OPENROUTER_API_KEY=your_key_here`
    `MONGODB_URI=your_mongodb_uri` (Optional: defaults to localhost)

### 2. Extension Setup
1.  Open Chrome and navigate to `chrome://extensions`.
2.  Enable **Developer mode** (top right).
3.  Click **Load unpacked** and select the `/extension` folder.

### 4. Running the Project
*   **Backend**: `uvicorn main:app --reload --port 8000`
*   **Dashboard**: `cd webapp && npm install && npm run dev`

---

## 🧠 How It Works: The Multi-Agent Pipeline

Kryptos-AI uses a structured "Scout → Analyst → Educator" pipeline to process threats:

1.  **Scout Agent** (First Response):
    *   Performs lightweight keyword analysis and URL scanning.
    *   Calculates an initial risk score and decides whether to escalate to deep analysis.
2.  **Analyst Agent** (Deep Inspection):
    *   Uses LLMs (Gemini 2.0 via OpenRouter) to identify specific threat types.
    *   Maps threats to **MITRE ATT&CK** techniques and gathers evidence.
3.  **Educator Agent** (User Guidance):
    *   Translates complex technical analysis into clear, actionable advice.
    *   Generates "Next Steps" and defensive learning points for the user.
4.  **Orchestrator**:
    *   Manages the data flow between agents.
    *   Broadcasts results in real-time to the Webapp using **WebSockets**.

---

## 🛡️ Security Notes
*   **API Safety**: Never commit your `.env` file. Ensure `OPENROUTER_API_KEY` is kept private.
*   **Privacy**: The extension includes **Localhost Exceptions** to avoid scanning local development environments.
*   **Screenshot Analysis**: Image data is converted to Base64 and processed securely via vision models.

---

## 🛠️ Troubleshooting

| Issue | Solution |
| :--- | :--- |
| **Port Conflict (WinError 10013)** | Run backend on 8001: `uvicorn main:app --port 8001` then update `BACKEND_URL` in `extension/background.js`. |
| **Extension not working** | Ensure the backend is running and click the **Refresh** icon in `chrome://extensions`. |
| **MongoDB Errors** | If not using a remote Atlas DB, ensure MongoDB is running locally on port 27017. |
| **Reload Loop** | If Uvicorn reloads constantly, use `--reload-exclude venv`. |

---

## 📚 Learning Resources
*   [FastAPI Documentation](https://fastapi.tiangolo.com/)
*   [Chrome Extension: Manifest V3 Guide](https://developer.chrome.com/docs/extensions/mv3/intro/)
*   [OpenRouter Vision API](https://openrouter.ai/docs#models)
*   [Vite + React Quickstart](https://vitejs.dev/guide/)
