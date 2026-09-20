#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================"
echo "  威胁情报自动化提取与分析平台"
echo "========================================"
echo ""
echo "[Working Dir] $SCRIPT_DIR"

# --- Python ---
PY=""
command -v python3 >/dev/null 2>&1 && PY=python3
[ -z "$PY" ] && command -v python >/dev/null 2>&1 && PY=python
if [ -z "$PY" ]; then
    echo "[ERROR] Python 3.10+ not found"
    exit 1
fi
echo "[OK] $($PY --version)"

# --- Node ---
command -v node >/dev/null 2>&1 || { echo "[ERROR] Node.js not found"; exit 1; }
echo "[OK] Node $(node --version)"
echo ""

# --- .env ---
if [ ! -f "backend/.env" ]; then
    echo "[Setup] Creating backend/.env ..."
    cp backend/.env.example backend/.env
    echo "[Setup] Edit backend/.env to set DEEPSEEK_API_KEY"
    echo ""
fi

# --- pip install ---
$PY -c "import fastapi" 2>/dev/null || {
    echo "[Install] Python dependencies..."
    $PY -m pip install -r backend/requirements.txt -q || {
        echo "[ERROR] pip install failed"
        exit 1
    }
    echo "[OK] Python deps installed"
}

# --- npm install ---
[ ! -d "frontend/node_modules" ] && {
    echo "[Install] npm dependencies..."
    cd frontend && npm install && cd "$SCRIPT_DIR"
    echo "[OK] npm deps installed"
}

echo ""
echo "========================================"
echo "  Starting services..."
echo "  Backend  : http://localhost:8000"
echo "  Frontend : http://localhost:5173"
echo "  API Docs : http://localhost:8000/docs"
echo "========================================"
echo ""

cleanup() {
    echo ""
    echo "Stopping services..."
    kill $BPID 2>/dev/null
    kill $FPID 2>/dev/null
    exit 0
}
trap cleanup SIGINT SIGTERM

cd "$SCRIPT_DIR/backend" && $PY main.py &
BPID=$!
cd "$SCRIPT_DIR"

sleep 2

cd "$SCRIPT_DIR/frontend" && npm run dev &
FPID=$!
cd "$SCRIPT_DIR"

echo "Press Ctrl+C to stop all services"
wait
