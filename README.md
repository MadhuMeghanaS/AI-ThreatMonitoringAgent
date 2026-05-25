# 🛡️ ThreatWatch AI — Security Threat Monitoring Agent

> AI-powered kill-chain detection with MITRE ATT&CK mapping and Claude-generated analyst reports.

## Architecture

```
Raw logs (JSON)
    │
    ▼
AnomalyDetector      ← per-user behavioral baselines + 8 scoring rules
    │
    ▼
KillChainBuilder     ← groups events into attack sequences, maps to MITRE ATT&CK
    │
    ▼
NarrativeGenerator   ← Claude API → plain-English analyst report per chain
    │
    ▼
Streamlit Dashboard  ← live event feed, priority queue, analytics, MITRE heatmap
```

## Setup (5 minutes)

```bash
# 1. Clone / enter the project folder
cd threat_agent

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set your Gemini API key
export GEMINI_API_KEY="AIza..."   # Windows: set GEMINI_API_KEY=AIza...

# 5. Generate sample log data
python generate_logs.py

# 6. Launch the dashboard
streamlit run app.py
```

Open http://localhost:8501 in your browser.

## Demo walkthrough

1. **Kill-chain alerts tab** — shows detected attack chains sorted by severity
2. Click **"Generate AI report"** on any P0 chain — Gemini explains the attack in plain English
3. **Event feed tab** — toggle "high-risk only" to filter the noise
4. **Analytics tab** — time-series event distribution and user risk ranking
5. **MITRE coverage tab** — which ATT&CK techniques were observed and how often

## Attack scenario planted in sample data

| Time  | Event                         | MITRE Tactic            | Score |
|-------|-------------------------------|-------------------------|-------|
| 23:00 | 15× auth failures (alice)     | Credential Access T1110 | 70    |
| 23:06 | Successful login (alice)      | Initial Access T1078    | 80    |
| 23:08 | Access /admin/users           | Privilege Escalation    | 65    |
| 23:10 | New account created           | Persistence T1136       | 75    |
| 23:12 | svc_monitor → DB server       | Lateral Movement T1021  | 60    |
| 23:15 | 155 MB export from DB         | Exfiltration T1041      | 100   |

## Extending for production

- **Real log ingest**: Replace `sample_logs.json` with a Kafka consumer or SIEM webhook
- **Persistent baselines**: Store entity profiles in Redis or Postgres
- **Graph store**: Use Neo4j for the kill-chain graph (better for complex multi-hop queries)
- **Fine-tuned scoring**: Add Isolation Forest on top of the rule-based scorer
- **Alerting**: Webhook to Slack/PagerDuty when P0 chain is detected
- **Analyst feedback**: "Mark as false positive" button updates entity baseline

## Tech stack

| Layer          | Technology                        |
|----------------|-----------------------------------|
| Log processing | Python, Pandas                    |
| Anomaly detect | Rule-based + statistical z-score  |
| Kill-chain     | NetworkX + MITRE ATT&CK patterns  |
| AI narratives  | Google Gemini (gemini-1.5-flash)  |
| Dashboard      | Streamlit + Plotly                |
| Data store     | JSON flat file (hackathon)        |
