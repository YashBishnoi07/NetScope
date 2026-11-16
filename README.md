# NetScope

NetScope is a live network traffic analysis dashboard and packet capture demo. It combines a FastAPI backend with a React/Vite frontend to decode packet metadata, aggregate traffic statistics, detect suspicious behavior, and expose both REST and WebSocket endpoints for a real-time monitor.

## Current status

This project now includes a working baseline implementation with:
- a live simulator-driven packet source and a demo PCAP replay path
- FastAPI endpoints for health, capture control, overview, protocol stats, ports, alerts, hosts, sessions, and packet/flow detail lookups
- real-time WebSocket snapshot updates
- a packet decoder for common packet families such as TCP, UDP, ICMP, DNS, and ARP
- a lightweight detector engine for port scan, SYN flood, ICMP flood, DNS tunneling, and ARP spoofing patterns
- a responsive dashboard with live status cards, packet drilldown, flow/session views, and alert feed
- backend tests and frontend tests/build validation

## Tech stack

- Backend: Python 3.12, FastAPI, Scapy, Pydantic, SQLAlchemy
- Frontend: React 18, TypeScript, Vite
- Testing: pytest, Vitest
- Containerization: Docker / Docker Compose

## Quick start

1. Open a terminal in the project root.
2. Start the backend:
   ```bash
   cd backend
   ..\.venv\Scripts\python.exe -m uvicorn netscope.app:app --host 0.0.0.0 --port 8000
   ```
3. In another terminal, start the frontend:
   ```bash
   cd frontend
   npm run dev -- --host 0.0.0.0 --port 5173
   ```
4. Open http://localhost:5173

## Example API routes

- `GET /api/v1/health`
- `GET /api/v1/capture/status`
- `POST /api/v1/capture/start`
- `POST /api/v1/capture/stop`
- `GET /api/v1/stats/overview`
- `GET /api/v1/stats/protocols`
- `GET /api/v1/stats/ports`
- `GET /api/v1/alerts`
- `GET /api/v1/hosts`
- `WebSocket /api/v1/ws`

## Validation

Run the checks below from the project root:

```bash
cd backend
..\.venv\Scripts\python.exe -m pytest -q

cd ../frontend
npm test
npm run build
```

## Notes

This remains a strong working demo and a solid foundation for a fuller NetScope implementation. The next major steps would be deeper packet-layer parsing, richer dashboards, more complete capture sources, and database-backed sessions.
