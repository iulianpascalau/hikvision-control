#!/bin/bash
set -e

# Configuration
PROJECT_DIR="/home/ubuntu/unifi-control"
BACKEND_SERVICE="unifi-control-backend"

# Check argument
VERSION_ARG=$1
if [ -z "$VERSION_ARG" ]; then
    echo "Usage: $0 <branch_or_tag_or_latest>"
    echo "Example: $0 main"
    echo "Example: $0 latest"
    exit 1
fi

# Navigate to project directory
if [ ! -d "$PROJECT_DIR" ]; then
    echo "Error: Project directory $PROJECT_DIR does not exist."
    exit 1
fi
cd "$PROJECT_DIR"

# Resolve "latest" if needed
BRANCH=$VERSION_ARG
if [ "$VERSION_ARG" == "latest" ]; then
    echo "Fetching latest tag..."
    git fetch --all --tags
    BRANCH=$(git describe --tags --abbrev=0 $(git rev-list --tags --max-count=1))
    if [ -z "$BRANCH" ]; then
        echo "Error: No tags found. Cannot determine 'latest'."
        exit 1
    fi
fi

echo "=========================================="
echo "Starting deployment for: $BRANCH"
echo "=========================================="

# 1. Stop Services
echo "Step 1: Stopping services..."
sudo systemctl stop $BACKEND_SERVICE || echo "Backend service not found or not running, skipping stop."
# Clean up old frontend service if it exists
if systemctl list-unit-files | grep -q "^unifi-control-frontend.service"; then
    echo "Found legacy frontend service. Disabling and stopping..."
    sudo systemctl stop unifi-control-frontend || true
    sudo systemctl disable unifi-control-frontend || true
fi

# 2. Checkout Code
echo "Step 2: Checking out code..."
git fetch --all
git checkout "$BRANCH"
git pull origin "$BRANCH"

# 3. Recompile Backend
echo "Step 3: Recompiling Backend..."
# Load common functions
source ./scripts/common.sh

#Ensure build tools are installed
ensure_tools_installed
# Ensure Go is installed
ensure_go_installed
GO_CMD="go"

$GO_CMD build -v -ldflags="-X main.appVersion=$(git describe --tags --long --dirty)" -o unifi-control main.go
if [ $? -ne 0 ]; then
    echo "Backend build failed!"
    exit 1
fi
echo "Backend build successful."

# 4. Update Frontend
echo "Step 4: Building Frontend for Production..."
ensure_node_yarn_installed
cd frontend
# Install dependencies
npm install
# Run production build
npm run build
if [ ! -d "dist" ]; then
    echo "Frontend build failed! 'dist' directory not found."
    exit 1
fi
echo "Frontend production build successful."
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

echo "=========================================="
echo "Deployment Finished Successfully!"
echo "=========================================="
