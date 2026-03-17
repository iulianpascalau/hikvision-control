# 🛰️ Unifi Control

A premium, state-of-the-art specialized dashboard for controlling PoE (Power over Ethernet) ports on Ubiquiti UniFi network devices. Designed for seamless camera maintenance and real-time network visibility.

![Login Page](docs/login.png)

## ✨ Core Features

- **🚀 Dynamic Auto-Discovery**: Automatically maps cameras to their physical switch ports using MAC addresses. No manual port configuration required.
- **📊 Real-time Monitoring**: Live tracking of PoE metrics including Power (W), Voltage (V), Current (mA), and PoE Class.
- **🔗 Hardware Transparency**: Explicitly shows which physical switch and port each camera is connected to.
- **📱 Responsive Design**: A high-end, dark-mode glassmorphism interface optimized for both desktop and mobile (iOS/Android).
- **🔒 Secure Access**: JWT-based authentication for the control panel.
- **⚡ Proactive Refreshes**: Background auto-refresh every minute and a manual floating refresh action.

![Dashboard](docs/dashboard.png)

## 🛠️ Setup & Deployment

The easiest way to deploy the solution is using the provided automated scripts.

### Automated Deployment

Run the unified deployment script with the desired version tag:

```bash
git clone https://github.com/iulianpascalau/unifi-control.git
cd unifi-control/scripts
./deploy.sh latest
```

This script handles:
1. Backend compilation and systemd service setup.
2. **Integrated Frontend Build**: Compiles the React UI and configures the Go server to serve it.
3. Automated dependency management (Go, Node.js).

### Configuration

Ensure your `config.toml` is configured with your cameras' MAC addresses and the path to the built frontend:

```toml
ListenAddress = ":8080"
FrontendPath = "frontend/dist"

[[Ports]]
Name = "Garden Camera"
CameraMAC = "00:11:22:33:44:55" # Auto-discovery
# SwitchMAC and Port can be omitted if CameraMAC is provided
```

also, the `.env` file should be configured with your Unifi credentials. It is always a good practice to not use 
your Unifi `admin` credentials. Users can be created in the Unifi dashboard (admin users with username and password, not requiring email) 

## 👨‍💻 Development

The project uses a standard Makefile for common development tasks.

| Command             | Action                                               |
|---------------------|------------------------------------------------------|
| `make build`        | Compiles the backend with version metadata           |
| `make run-backend`  | Starts the Go server with DEBUG logging              |
| `make run-frontend` | Installs dependencies and starts the Vite dev server |
| `make tests`        | Executes the backend test suite                      |

---

Built with ❤️ by [Iulian Pascalau](https://github.com/iulianpascalau)
