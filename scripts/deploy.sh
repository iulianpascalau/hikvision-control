#!/bin/bash
set -e

# Configuration
PROJECT_DIR="/home/ubuntu/unifi-control"
BACKEND_SERVICE="unifi-control-backend"
FRONTEND_SERVICE="unifi-control-frontend"

# Check argument
BRANCH=$1
if [ -z "$BRANCH" ]; then
    echo "Usage: $0 <branch_or_tag>"
    echo "Example: $0 main"
    exit 1
fi

echo "=========================================="
echo "Starting deployment for branch: $BRANCH"
echo "=========================================="

# Navigate to project directory
if [ ! -d "$PROJECT_DIR" ]; then
    echo "Error: Project directory $PROJECT_DIR does not exist."
    exit 1
fi
cd "$PROJECT_DIR"

# 1. Stop Services
echo "Step 1: Stopping services..."
sudo systemctl stop $FRONTEND_SERVICE $BACKEND_SERVICE || echo "Services not found or not running, skipping stop."

# 2. Checkout Code
echo "Step 2: Checking out code..."
git fetch --all
git checkout "$BRANCH"
git pull origin "$BRANCH"

# 3. Recompile Backend
echo "Step 3: Recompiling Backend..."
# Load common functions
source ./scripts/common.sh

# Ensure Go is installed
ensure_go_installed
GO_CMD="go"

cd ./services/proxy
$GO_CMD build -v -ldflags="-X main.appVersion=$(git describe --tags --long --dirty)" -o epoch-proxy-server main.go
if [ $? -ne 0 ]; then
    echo "Backend build failed!"
    exit 1
fi
echo "Backend build successful."

# 4. Update Frontend
echo "Step 4: Updating Frontend..."
cd ../../frontend
# Install dependencies
npm install
# Note: The service currently runs 'npm run dev', so we don't 'build' for production serving yet.
# If you switch to 'npm run build', add it here.
cd ..

# 5. Restart Services
echo "Step 5: Restarting services..."

# Backend
if systemctl cat $BACKEND_SERVICE > /dev/null 2>&1; then
    sudo systemctl start $BACKEND_SERVICE
else
    echo "Service $BACKEND_SERVICE not found. Creating it..."
    chmod +x "$PROJECT_DIR/scripts/create_backend_service.sh"
    "$PROJECT_DIR/scripts/create_backend_service.sh"
fi

# Frontend
if systemctl cat $FRONTEND_SERVICE > /dev/null 2>&1; then
    sudo systemctl start $FRONTEND_SERVICE
else
    echo "Service $FRONTEND_SERVICE not found. Creating it..."
    chmod +x "$PROJECT_DIR/scripts/create_frontend_service.sh"
    "$PROJECT_DIR/scripts/create_frontend_service.sh"
fi

# 6. Monitor
echo "Step 6: Monitoring status..."
sleep 5

if systemctl is-active --quiet $BACKEND_SERVICE; then
    echo "✅ $BACKEND_SERVICE is active."
else
    echo "❌ $BACKEND_SERVICE failed to start."
    sudo journalctl -u $BACKEND_SERVICE -n 20 --no-pager
    exit 1
fi

if systemctl is-active --quiet $FRONTEND_SERVICE; then
    echo "✅ $FRONTEND_SERVICE is active."
else
    echo "❌ $FRONTEND_SERVICE failed to start."
    sudo journalctl -u $FRONTEND_SERVICE -n 20 --no-pager
    exit 1
fi

echo "=========================================="
echo "Deployment Finished Successfully!"
echo "=========================================="
