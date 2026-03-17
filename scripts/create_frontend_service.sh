#!/bin/bash

# Configuration - MUST MATCH YOUR VM SETUP
USER_NAME="ubuntu"
APP_NAME="unifi-control-frontend"
APP_DIR="/home/${USER_NAME}/unifi-control/frontend"

# We need the absolute path to npm. 
# On the VM, run `which npm` to find it. 
# Common paths: /usr/bin/npm, /usr/local/bin/npm, or under .nvm
# We will try to dynamically find it if possible, otherwise default to /usr/bin/npm
NPM_PATH=$(which npm)
if [ -z "$NPM_PATH" ]; then
    NPM_PATH="/usr/bin/npm"
fi
# If you use NVM, you might often need to hardcode the specific version path, e.g.:
# NPM_PATH="/home/ubuntu/.nvm/versions/node/v18.16.0/bin/npm"

# Create the service file content
SERVICE_CONTENT="[Unit]
Description=Mvx Unifi control React Frontend
After=network-online.target

[Service]
User=${USER_NAME}
WorkingDirectory=${APP_DIR}
Environment=PATH=/usr/bin:/usr/local/bin
# Command to start vite server
ExecStart=${NPM_PATH} run dev -- --host
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"

# Path to the systemd service file
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"

# Write the service file
echo "Creating systemd service file at ${SERVICE_FILE}..."
echo "Using NPM path: ${NPM_PATH}"
sudo bash -c "echo '${SERVICE_CONTENT}' > ${SERVICE_FILE}"

# Reload systemd daemon
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable the service
echo "Enabling ${APP_NAME} service..."
sudo systemctl enable ${APP_NAME}

# Start the service
echo "Starting ${APP_NAME} service..."
sudo systemctl start ${APP_NAME}

# Show status
echo "Service status:"
sudo systemctl status ${APP_NAME} --no-pager
