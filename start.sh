#!/usr/bin/env bash
# NetSentinel — Docker launcher
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     "
echo "  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     "
echo "  ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     "
echo "  ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     "
echo "  ██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ "
echo "  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
echo -e "${NC}"
echo -e "${CYAN}  Network Packet Analyzer & IDS Engine v3.0${NC}"
echo ""

# Verificar Docker
if ! command -v docker &>/dev/null; then
  echo -e "${RED}[ERROR] Docker no está instalado.${NC}"
  echo "  Instálalo desde: https://docs.docker.com/get-docker/"
  exit 1
fi

if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
  echo -e "${RED}[ERROR] Docker Compose no encontrado.${NC}"
  exit 1
fi

# Detectar comando compose
COMPOSE="docker compose"
if ! docker compose version &>/dev/null 2>&1; then
  COMPOSE="docker-compose"
fi

echo -e "${YELLOW}[1/3] Construyendo imágenes...${NC}"
$COMPOSE build --quiet

echo -e "${YELLOW}[2/3] Levantando servicios...${NC}"
$COMPOSE up -d

echo -e "${YELLOW}[3/3] Verificando servicios...${NC}"
sleep 3

BACKEND_OK=false
FRONTEND_OK=false

for i in {1..10}; do
  if curl -sf http://localhost:8765/ > /dev/null 2>&1; then
    BACKEND_OK=true; break
  fi
  sleep 1
done

if curl -sf http://localhost:3000/ > /dev/null 2>&1; then
  FRONTEND_OK=true
fi

echo ""
echo -e "${GREEN}┌─────────────────────────────────────────┐${NC}"
echo -e "${GREEN}│         NetSentinel v3.0 — ONLINE        │${NC}"
echo -e "${GREEN}└─────────────────────────────────────────┘${NC}"
echo ""
echo -e "  Frontend UI  →  ${CYAN}http://localhost:3000${NC}"
echo -e "  Backend API  →  ${CYAN}http://localhost:8765${NC}"
echo -e "  WebSocket    →  ${CYAN}ws://localhost:8765/ws${NC}"
echo ""

if $BACKEND_OK; then
  echo -e "  Backend:  ${GREEN}✔ ONLINE${NC}"
else
  echo -e "  Backend:  ${RED}✘ No responde — revisa: docker compose logs backend${NC}"
fi

if $FRONTEND_OK; then
  echo -e "  Frontend: ${GREEN}✔ ONLINE${NC}"
else
  echo -e "  Frontend: ${YELLOW}⚠ Puede estar iniciando aún${NC}"
fi

echo ""
echo -e "${YELLOW}  Para detener:  docker compose down${NC}"
echo -e "${YELLOW}  Para logs:     docker compose logs -f${NC}"
echo ""

# Abrir en el navegador automáticamente
if command -v xdg-open &>/dev/null; then
  xdg-open http://localhost:3000 &>/dev/null &
elif command -v open &>/dev/null; then
  open http://localhost:3000 &>/dev/null &
fi
