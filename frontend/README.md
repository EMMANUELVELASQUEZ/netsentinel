# NetSentinel v3.0 — Network Packet Analyzer & IDS

Sistema de análisis de paquetes de red de máxima seguridad con motor IDS integrado,
interfaz profesional estilo terminal y captura real con Scapy.

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────┐
│                     NETSENTINEL v3.0                    │
├──────────────────────┬──────────────────────────────────┤
│   BACKEND (Python)   │       FRONTEND (HTML/JS)         │
│                      │                                  │
│  FastAPI + Scapy     │   Interfaz terminal-grade        │
│  WebSocket streaming │   IDS engine (client mirror)     │
│  IDS Engine (7 rules)│   Hex dump viewer                │
│  REST API            │   Protocol distribution          │
│  Simulation fallback │   Threat feed en tiempo real     │
└──────────────────────┴──────────────────────────────────┘
```

## Estructura del proyecto

```
netsentinel/
├── backend/
│   ├── main.py           # FastAPI + Scapy + IDS Engine
│   └── requirements.txt  # Dependencias Python
└── frontend/
    └── index.html        # UI completa (zero dependencies)
```

---

## Instalación y ejecución

### Backend

```bash
cd backend

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar (requiere privilegios para captura real)
sudo python main.py
```

El backend corre en `http://localhost:8765`

### Frontend

```bash
# Opción 1: Abrir directamente (modo simulación)
open frontend/index.html

# Opción 2: Servidor local (conecta al backend WebSocket)
cd frontend
python3 -m http.server 3000
# Abrir http://localhost:3000
```

---

## API Endpoints

| Método | Ruta              | Descripción                          |
|--------|-------------------|--------------------------------------|
| GET    | /                 | Info del servicio + versión Scapy    |
| GET    | /interfaces       | Lista de interfaces de red           |
| GET    | /stats            | Estadísticas de la sesión actual     |
| POST   | /capture/start    | Inicia captura (param: iface=eth0)   |
| POST   | /capture/stop     | Detiene captura                      |
| WS     | /ws               | Stream de paquetes en tiempo real    |

---

## Motor IDS — Reglas de detección

| Regla             | Severidad | Umbral                                    |
|-------------------|-----------|-------------------------------------------|
| SYN Flood         | CRITICAL  | >100 SYN/10s desde mismo IP               |
| Port Scan         | HIGH      | >20 puertos destino únicos en 5s          |
| DNS Amplification | HIGH      | Respuesta DNS grande a query pequeño      |
| ICMP Flood        | MEDIUM    | >50 ICMP/10s desde mismo IP               |
| SSH Brute Force   | HIGH      | >15 conexiones a puerto 22 en 30s         |
| ARP Spoofing      | CRITICAL  | ARP reply no solicitado (cache poison)    |
| Oversized Frame   | LOW       | Paquete >1400 bytes                       |

---

## Seguridad — Consideraciones de producción

### Privilegios mínimos (Linux)
```bash
# En vez de sudo completo, otorgar solo CAP_NET_RAW
sudo setcap cap_net_raw+eip /usr/bin/python3
```

### Autenticación JWT (production)
Agregar al backend:
```bash
pip install python-jose[cryptography] passlib
```

```python
# Proteger endpoints con:
from fastapi.security import HTTPBearer
security = HTTPBearer()

@app.post("/capture/start")
async def start(credentials: HTTPAuthorizationCredentials = Depends(security)):
    verify_token(credentials.credentials)
    ...
```

### TLS/mTLS
```bash
uvicorn main:app --ssl-keyfile=key.pem --ssl-certfile=cert.pem
```

### Separación de procesos
```
[Proceso privilegiado: captura raw]
        ↓ Unix socket (permisos 600)
[Proceso sin privilegios: API FastAPI]
        ↓ WebSocket TLS
[Navegador: Frontend]
```

---

## Roadmap de funcionalidades

- [ ] Exportación `.pcap` real (usando dpkt/scapy)
- [ ] Reglas IDS configurables (YAML)
- [ ] Base de datos SQLite para historial de sesiones
- [ ] Dashboard de estadísticas con graficas Chart.js
- [ ] Notificaciones email/Slack en amenaza CRITICAL
- [ ] Integración con Suricata para IDS avanzado
- [ ] Modo headless (CLI puro con Rich)
- [ ] Docker Compose para deployment rápido

---

## Dependencias

**Backend:**
- `fastapi` — Framework API async
- `uvicorn` — ASGI server
- `scapy` — Captura y análisis de paquetes
- `websockets` — Protocolo WebSocket

**Frontend:** Zero dependencias externas — HTML/CSS/JS puro.

---

NetSentinel v3.0 — Built with precision.
