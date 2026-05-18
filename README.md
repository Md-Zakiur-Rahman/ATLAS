# 🛡️ ATLAS - Blue Team Threat Detection System

<!-- Add project description here -->

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [Database](#database)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

ATLAS is a comprehensive Blue Team Threat Detection System designed to monitor, analyze, and respond to security threats in real-time. Built with a modern GUI interface powered by customtkinter, ATLAS provides security teams with actionable intelligence through event logging, threat analysis, network monitoring, and automated reporting. The system leverages Supabase for scalable cloud-based data storage and includes advanced features like hash-chain tamper detection, file encryption/decryption, and device fingerprinting.

## ✨ Features

- **Real-Time Event Logging**: Capture and log security events with timestamp precision
- **Threat Detection & Analysis**: Automated threat scoring and anomaly detection
- **Hash-Chain Tamper Detection**: Verify log integrity with cryptographic hash chains
- **Network Monitoring**: Track and analyze network connections with IP threat flagging
- **Interactive Timeline Visualization**: View events on an interactive timeline with matplotlib integration
- **File Encryption/Decryption**: Secure file operations with built-in encryption tools
- **Automated Report Generation**: Generate comprehensive PDF threat reports
- **User Authentication**: Secure login and demo mode for testing
- **Event Filtering & Search**: Advanced filtering by severity, type, and time range
- **CSV Export**: Export logs and reports for external analysis
- **Device Fingerprinting**: Identify and track devices accessing the system
- **Windows Installer**: Standalone executable with InnoSetup installer

## 📁 Project Structure

```
ATLAS/
├── README.md                          # This file
├── main.py                            # Main application entry point
├── requirements.txt                   # Python dependencies
│
├── dashboard/                         # UI Layer (customtkinter)
│   ├── __init__.py
│   ├── app.py                         # Main application window & authentication
│   ├── dashboard_tab.py               # System metrics & threat overview
│   ├── logs_tab.py                    # Event log viewer
│   ├── timeline_tab.py                # Event timeline visualization
│   ├── network_tab.py                 # Network connections monitoring
│   ├── encrypt_tab.py                 # File encryption/decryption UI
│   ├── report_tab.py                  # Report generation
│   ├── settings_tab.py                # Application settings
│   ├── alerts.py                      # Alert notifications
│   ├── animations.py                  # UI animations
│   ├── ui_polish.py                   # UI enhancements
│   ├── pdf_generator.py               # PDF report generation
│   └── animations.py                  # Visual effects
│
├── database/                          # Database Layer (Supabase)
│   ├── __init__.py
│   ├── db_manager.py                  # Supabase client & queries
│   └── schema.sql                     # Database schema definition
│
├── logs/                              # Generated logs & reports
│   ├── events_export_*.csv            # Exported event logs
│   └── threat_report_*.csv            # Exported threat reports
│
├── build_windows.bat                  # Windows build script
├── build_windows.ps1                  # PowerShell build script
├── build.spec                         # PyInstaller configuration
│
├── test_day1.py                       # Initial test file
├── test_day3_integration.py           # Integration tests
├── test_sqlite_simple.py              # SQLite tests (legacy)
└── test_supabase.py                   # Supabase connection tests
```

## 🚀 Installation

### Prerequisites

- **Python 3.10+** (3.10.11 or higher recommended)
- **pip** (Python package manager)
- **Windows 10/11** for GUI application
- **Internet connection** for Supabase cloud database connectivity
- **Supabase account** (free tier available) for database backend

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/Md-Zakiur-Rahman/ATLAS.git
   cd ATLAS
   ```

2. **Create a virtual environment (optional but recommended)**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   - Create a `.env` file in the project root
   - Add your Supabase credentials:
     ```
     SUPABASE_URL=your_supabase_url
     SUPABASE_KEY=your_supabase_key
     ```

5. **Initialize the database**
   - Run the schema from `database/schema.sql` in your Supabase project

6. **Run the application**
   ```bash
   python main.py
   ```

## 💻 Usage

### Running the Application

```bash
python main.py
# or
cd dashboard && python app.py
```

### Demo Mode

ATLAS includes a built-in demo mode for testing and evaluation without requiring database connectivity. Demo mode loads sample security events, threats, and network data. Launch the application with demo credentials to explore all features without a live Supabase instance.

## 🏗️ Architecture

### Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **UI** | customtkinter 5.2.0 | Modern Python GUI |
| **Database** | Supabase (PostgreSQL) | Cloud database |
| **Backend** | Python 3.10+ | Core logic |
| **Reports** | ReportLab | PDF generation |
| **Visualization** | Matplotlib | Charts & graphs |

### Module Descriptions

#### Dashboard (`dashboard/`)

**app.py**
- Application entry point
- Login/authentication screen
- Demo mode data loading
- Tab management

**dashboard_tab.py**
- System metrics overview
- Threat level calculation
- Event statistics
- Anomaly scoring

**logs_tab.py**
- Event log viewer
- Severity filtering
- Hash chain verification
- Event details display

**timeline_tab.py**
- Event timeline visualization
- Matplotlib scatter plot
- Event selection & details
- Time-based filtering

**network_tab.py**
- Network connection monitoring
- IP threat flagging
- Connection details
- Geographic information

**encrypt_tab.py**
- File encryption interface
- File decryption interface
- Encryption operation logging

**report_tab.py**
- Report generation UI
- Multiple report types
- Export functionality

**settings_tab.py**
- Application configuration
- User preferences
- System settings

#### Database (`database/`)

**db_manager.py**
- Supabase client initialization
- Event logging functions
- Query functions for events/threats/network data
- Hash chain verification
- CSV export utilities
- DatabaseManager class for backward compatibility

**schema.sql**
- Database table definitions
- Column specifications
- Constraints & indexes
- Initial data structure

## 🗄️ Database

### Supabase Tables

**events**
- Event logging with hash-chaining

**threats**
- Threat records and analysis

**network_connections**
- Network activity logs

**auth**
- User authentication data

**rename_log**
- File rename tracking for ransomware detection

### Connection

ATLAS connects to Supabase using the official Python client library. The `db_manager.py` module handles all database operations including:
- Connection initialization with API credentials
- Asynchronous event logging and queries
- Hash-chain verification for tamper detection
- CSV export functionality
- Transaction management for data consistency

Connection details are loaded from environment variables for security.

## 📊 Data Flow

1. **Event Capture**: Security events are detected and captured from system/network sources
2. **Event Logging**: Events are logged to Supabase with hash-chain verification
3. **Threat Analysis**: The dashboard analyzes events to calculate threat scores and anomalies
4. **Visualization**: Events are displayed on timeline, network, and dashboard tabs
5. **Reporting**: Security analysts generate PDF reports with findings
6. **Export**: Data can be exported to CSV for external analysis tools
7. **Archive**: Historical data is retained in Supabase for compliance and forensics

## 🧪 Testing

### Test Files

- `test_day1.py` - Basic functionality tests
- `test_day3_integration.py` - Integration tests
- `test_supabase.py` - Database connectivity tests

### Running Tests

```bash
python test_supabase.py
python test_day3_integration.py
```

## 🔐 Security Features

<!-- Describe security features here -->

- Hash-chain tamper detection
- Device fingerprinting
- Encrypted file operations
- Secure authentication

## 🛠️ Building for Windows

### Using PyInstaller

```bash
python -m PyInstaller build.spec
```

### Using Batch Script

```bash
build_windows.bat
```

### Using PowerShell

```powershell
.\build_windows.ps1
```

## 📝 Requirements

See `requirements.txt` for all dependencies:

<!-- Key dependencies -->
- customtkinter==5.2.0
- supabase==2.0.0
- python-dotenv
- matplotlib
- reportlab
- cryptography

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository** and create a feature branch
2. **Follow the existing code style** and conventions
3. **Add tests** for new functionality
4. **Update documentation** as needed
5. **Commit with clear messages** describing changes
6. **Submit a pull request** with a description of your changes

### Development Setup

```bash
# Install with development dependencies
pip install -r requirements.txt

# Run tests
python test_day3_integration.py
python test_supabase.py
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📧 Contact & Support

- **Repository**: [github.com/Md-Zakiur-Rahman/ATLAS](https://github.com/Md-Zakiur-Rahman/ATLAS)
- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Join community discussions for questions and ideas
- **Email**: Contact through GitHub profile

## 🔄 Version History

### v1.0.0 (May 2026)
- Initial release
- Core threat detection and monitoring
- Real-time event logging with hash-chain verification
- Network monitoring and analysis
- PDF report generation
- File encryption/decryption utilities
- Windows installer support

---

**Last Updated:** May 2026
**Current Version:** 1.0.0
**Database:** Supabase PostgreSQL
**Python:** 3.10.11
