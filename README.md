# CVE Watcher

A FastAPI-based application for monitoring and tracking CVE (Common Vulnerabilities and Exposures) vulnerabilities for your software assets.

## Overview

CVE Watcher helps organizations and developers monitor their software assets for security vulnerabilities by:

- **Asset Management**: Track your software components, versions, and CPE identifiers
- **CVE Monitoring**: Automatically monitor for new vulnerabilities affecting your assets
- **Real-time Alerts**: Get notified when new CVEs are discovered for your tracked software
- **Vulnerability Reports**: Generate detailed reports on security issues affecting your infrastructure
- **User Management**: Secure user authentication and authorization

## Features

- 🔐 **User Authentication**: Secure JWT-based authentication system
- 📦 **Asset Tracking**: Manage your software inventory with detailed metadata
- 🔍 **CVE Monitoring**: Integration with NIST NVD for real-time vulnerability data
- 📊 **Severity Filtering**: Filter vulnerabilities by severity level (Critical, High, Medium, Low)
- 📈 **Reporting**: Generate monitoring reports and vulnerability summaries
- 🎯 **Targeted Scanning**: Monitor specific assets or scan all assets at once
- 🔄 **Real-time Updates**: Automatic vulnerability detection and updates

## API Endpoints

### Authentication

- `POST /auth/register` - Register new user
- `POST /auth/login` - User login
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Logout user

### Asset Management

- `POST /assets/` - Create new asset
- `GET /assets/` - List user's assets
- `GET /assets/{asset_id}` - Get specific asset details
- `PATCH /assets/{asset_id}` - Update asset information
- `DELETE /assets/{asset_id}` - Remove asset

### CVE Monitoring

- `GET /assets/{asset_id}/vulnerabilities` - Get vulnerabilities for specific asset
- `GET /assets/{asset_id}/monitor` - Monitor single asset for CVEs
- `POST /assets/monitoring/scan-all` - Scan all user assets
- `GET /assets/monitoring/report` - Generate monitoring report

### CVE Data

- `GET /cves/fetch-recent` - Fetch and store recent CVEs from NIST NVD
- `GET /cves/recent` - List recently stored CVEs
- `GET /cves/search` - Search CVEs by product (and optional version)
- `GET /cves/vulnerabilities` - Check vulnerabilities across all your assets

### User & Health

- `GET /user` - Get the current user's profile
- `GET /health` - Service health check

## Technology Stack

- **Backend**: FastAPI (Python)
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Authentication**: JWT with joserfc
- **Migration**: Alembic
- **Container**: Docker & Docker Compose
- **External API**: NIST NVD API integration

## Quick Start

### Using Docker (Recommended)

1. Clone the repository:

```bash
git clone https://github.com/mangrisano/cvewatcher.git
cd cvewatcher
```

2. Start the application:

```bash
docker-compose up --build
```

3. Access the API:

- API: http://localhost:8000
- Interactive API docs: http://localhost:8000/docs
- Alternative docs: http://localhost:8000/redoc

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is free software licensed under the [GNU General Public License v3.0](LICENSE).

---
