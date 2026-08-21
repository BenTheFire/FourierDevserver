# Fourier Games Server Monitoring Dashboard

A lightweight Flask-based monitoring dashboard for logs, host resources, network checks, Kubernetes visibility, processes, and Docker container monitoring.

## Features

- Central log ingestion and dashboard display
- Host resource monitoring (CPU, memory, top processes)
- Network target monitoring with ping checks and status lights
- Kubernetes monitoring panel with live or emulated results
- Docker container monitoring panel with running/stopped containers and volumes
- Basic authentication for the dashboard
- API key protection for log ingestion and metrics endpoints

## Default login

- Username: admin
- Password: changeme

You can override these with environment variables:

- ADMIN_USER
- ADMIN_PASSWORD

## Environment variables

- DATABASE_URL: database connection string (defaults to sqlite:///local_logs.db)
- SECRET_KEY: Flask session secret key
- MONITOR_SITE_URL: URL used for external network reachability checks
- PORT: Flask port (default: 5000)
- FLASK_DEBUG: enable debug mode (default: 1)

## Running the app

1. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

2. Start the app:
   ```bash
   python app.py
   ```

3. Open the dashboard in a browser:
   ```text
   http://localhost:5000/
   ```

## Monitoring behavior

- Kubernetes and Docker panels only show live data when the host actually has a working Kubernetes or Docker environment available.
- If no compatible runtime is detected, the app shows a warning banner and displays emulated sample data so the UI remains useful for testing and demos.

## API keys

Public endpoints that accept log submissions or metrics requests require an API key in the `X-API-Key` header.

## Notes

- The project stores local SQLite data by default.
- The dashboard and monitoring panels are intended for local or internal monitoring use.
