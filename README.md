# Network Admin System

An AI-Powered Network Device Management and Administration System with real-time monitoring, security analysis, and intelligent recommendations.

## 🚀 Features

### Network Discovery
- **Multi-protocol scanning**: ARP, Ping, Port scanning
- **Real-time device detection**: Automatic discovery of network devices
- **OS fingerprinting**: Operating system detection and identification
- **Device classification**: Automatic categorization by device type

### Security Analysis
- **Vulnerability assessment**: Automated security scanning
- **Risk scoring**: AI-powered risk evaluation for each device
- **Port analysis**: Detection of open ports and services
- **Security recommendations**: Intelligent suggestions for network hardening

### AI-Powered Administration
- **Network health monitoring**: Real-time performance tracking
- **Predictive analytics**: AI-driven insights and recommendations
- **Automated patching**: OS and security patch management
- **Intelligent alerts**: Smart notification system

### Modern Web Interface
- **Real-time dashboard**: Live network overview and statistics
- **Device management**: Comprehensive device information and controls
- **Responsive design**: Works on desktop and mobile devices
- **Dark theme**: Modern, professional interface

## 🏗️ Architecture

### Backend (Python/FastAPI)
- **FastAPI**: High-performance async web framework
- **SQLAlchemy**: Database ORM with SQLite
- **Scapy**: Network packet manipulation and scanning
- **Nmap**: Advanced network discovery and OS detection
- **WebSocket**: Real-time communication with frontend

### Frontend (React/TypeScript)
- **React 18**: Modern UI framework with hooks
- **TypeScript**: Type-safe development
- **Material-UI**: Professional component library
- **React Query**: Server state management
- **React Router**: Client-side routing

### AI Components
- **Risk Assessment**: Machine learning-based security scoring
- **Network Analysis**: Intelligent pattern recognition
- **Recommendation Engine**: AI-powered suggestions
- **Predictive Maintenance**: Proactive issue detection

## 📋 Prerequisites

### System Requirements
- **Python 3.8+**: Backend runtime
- **Node.js 16+**: Frontend development
- **Nmap**: Network scanning (install separately)
- **Administrator/root access**: Required for network scanning

### Windows Installation
```bash
# Install Nmap (required for network scanning)
# Download from: https://nmap.org/download.html

# Install Python dependencies
pip install -r requirements.txt

# Install Node.js dependencies
cd frontend
npm install
```

### Linux/macOS Installation
```bash
# Install Nmap
sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS

# Install Python dependencies
pip3 install -r requirements.txt

# Install Node.js dependencies
cd frontend
npm install
```

## 🚀 Quick Start

### Option 1: Automated Startup (Windows)
1. **Start Backend**: Double-click `start_backend.py`
2. **Start Frontend**: Double-click `start_frontend.bat`
3. **Access Application**: Open http://localhost:3001

### Option 2: Manual Startup
```bash
# Terminal 1: Start Backend
python start_backend.py

# Terminal 2: Start Frontend
cd frontend
npm start
```

### Option 3: Development Mode
```bash
# Backend with auto-reload
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8001

# Frontend with hot reload
cd frontend
npm start
```

## 📊 Usage

### 1. Network Discovery
- Navigate to **Dashboard** to see network overview
- Click **"Start Scan"** to begin device discovery
- View discovered devices in the **Devices** section

### 2. Device Management
- Browse all devices in the **Devices** page
- Search and filter devices by type, OS, or status
- Click on any device for detailed information

### 3. Security Analysis
- Check **Security Analysis** for vulnerability reports
- Review AI-generated risk scores
- Implement recommended security measures

### 4. AI Recommendations
- Visit **AI Recommendations** for intelligent suggestions
- Review network health score
- Follow priority action items

## 🔧 Configuration

### Network Settings
The system automatically detects your network range, but you can customize:

```python
# In backend/network_scanner.py
self.network_range = "192.168.1.0/24"  # Customize your network
self.scan_ports = [21, 22, 23, 80, 443, 8080]  # Customize ports
```

### Security Settings
```python
# In backend/ai_admin.py
self.risk_weights = {
    "open_ports": 0.3,
    "outdated_os": 0.25,
    "no_security_scan": 0.2,
    "unusual_activity": 0.15,
    "vulnerabilities": 0.1
}
```

## 🛡️ Security Considerations

### Network Scanning
- **Administrator access required**: Network scanning needs elevated privileges
- **Firewall configuration**: Ensure your firewall allows the application
- **Network policies**: Respect your organization's network policies
- **Scan frequency**: Adjust scan intervals to avoid network congestion

### Data Privacy
- **Local storage**: All data is stored locally in SQLite database
- **No external calls**: No data is sent to external services
- **Encryption**: Consider encrypting the database for sensitive environments

## 🔍 Troubleshooting

### Common Issues

**Backend won't start:**
```bash
# Check Python version
python --version  # Should be 3.8+

# Install dependencies
pip install -r requirements.txt

# Check Nmap installation
nmap --version
```

**Frontend won't start:**
```bash
# Check Node.js version
node --version  # Should be 16+

# Clear npm cache
npm cache clean --force

# Reinstall dependencies
cd frontend
rm -rf node_modules package-lock.json
npm install
```

**No devices discovered:**
- Ensure you're running as administrator/root
- Check firewall settings
- Verify network connectivity
- Review scan logs in `network_admin.log`

### Logs and Debugging
```bash
# Backend logs
tail -f network_admin.log

# Frontend logs
# Check browser console (F12)
```

## 🚀 Future Enhancements

### Planned Features
- **Automated patching**: OS and security update automation
- **Advanced AI**: Machine learning for anomaly detection
- **Mobile app**: Native mobile application
- **Cloud integration**: Multi-site network management
- **API integrations**: Third-party security tools
- **Reporting**: Advanced analytics and reporting

### AI Capabilities
- **Predictive maintenance**: Proactive issue detection
- **Behavioral analysis**: Device behavior monitoring
- **Threat intelligence**: Integration with threat feeds
- **Automated response**: Automatic security measures

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the logs for error details

---

**⚠️ Disclaimer**: This tool is for educational and legitimate network administration purposes only. Always ensure you have proper authorization before scanning any network. 