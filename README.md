# Azure-NSP-Analyzer

A Flask-based Azure Container App that queries Log Analytics workspaces through Network Security Perimeter (NSP) validation. This tool demonstrates secure access patterns and NSP security architecture for Azure resources.

<img width="634" height="399" alt="image" src="https://github.com/user-attachments/assets/b4fd4c02-4622-4d28-b0bc-bbfa95e8019d" />

<img width="632" height="492" alt="image" src="https://github.com/user-attachments/assets/daaf12b7-55d3-4627-872e-8eab6d2fee14" />


## Features

- **Network Security Perimeter Integration**: Demonstrates secure access to protected Log Analytics workspaces
- **Managed Identity Authentication**: Uses Azure Managed Identity for secure authentication (no credentials hardcoded)
- **Live Syslog Dashboard**: Real-time visualization of Log Analytics Syslog records with interactive search
- **Security Monitoring**: Tracks NSP validation results and security posture
- **Responsive UI**: Modern, dark-themed web interface with comprehensive security status
- **Health Checks**: Built-in health endpoint for Container Apps monitoring
- **NSP Error Analysis**: Extracts and displays detailed NSP validation failures

## Prerequisites

- Python 3.8+
- Azure subscription with:
  - Container Apps environment
  - Log Analytics Workspace
  - Network Security Perimeter enabled
- Azure CLI (for local testing and deployment)
- Docker (for containerization)

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/HashimsGitHub/Azure-NSP-Analyzer.git
cd Azure-NSP-Analyzer
```

### 2. Set Up Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` with your Log Analytics Workspace ID:

```env
LOG_ANALYTICS_WORKSPACE_ID=your-workspace-uuid-here
WORKSPACE_NAME=law-nsp-poc
NSP_SERVICE_TAG=ContainerAppsManagement.AustraliaEast
```

**Note**: The `.env` file is git-ignored and will NOT be uploaded to GitHub.

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Deployment

### Local Docker Build

```bash
docker build \
  --build-arg LOG_ANALYTICS_WORKSPACE_ID="your-workspace-id" \
  -t azure-nsp-analyzer:latest .
```

### Deploy to Azure Container Apps

```bash
# Build and push to registry
docker build -t azure-nsp-analyzer:latest .
docker tag azure-nsp-analyzer:latest YOUR_REGISTRY.azurecr.io/azure-nsp-analyzer:latest
docker push YOUR_REGISTRY.azurecr.io/azure-nsp-analyzer:latest

# Deploy to Container Apps
az containerapp create \
  --name azure-nsp-analyzer \
  --resource-group YOUR_RG \
  --environment YOUR_ENV \
  --image YOUR_REGISTRY.azurecr.io/azure-nsp-analyzer:latest \
  --env-vars LOG_ANALYTICS_WORKSPACE_ID="your-workspace-id" \
  --target-port 8080 \
  --ingress external
```

## API Endpoints

### `GET /`

Returns the HTML dashboard with live records from the workspace.

**Success Response (200)**:
- Displays connected workspace status
- Shows latest records 
- Displays executed Kusto query
- Shows security architecture overview

**Error Response (500)**:
- Indicates NSP validation failure
- Shows source IP attempting access
- Displays detailed NSP error codes and messages
- Provides security architecture diagram


### `GET /api/status`

JSON API endpoint for programmatic access to status and monitoring data.


**Success Response (200)**:
```json
{
  "status": "success",
  "identity": "Managed Identity",
  "workspace": "4cf1706d-4493-45ae-853e-3b87cf6ace86",
  "query": "Syslog | where TimeGenerated > ago(24h) | order by TimeGenerated desc | take 5",
  "rowCount": 5,
  "tableCount": 1,
  "sampleRecords": [
    {
      "TimeGenerated": "2024-01-15T10:30:00Z",
      "Computer": "vm-01",
      "ProcessName": "sshd",
      "SeverityLevel": "info",
      "SyslogMessage": "Connection closed"
    }
  ],
  "timestamp": "2024-01-15T10:30:00+00:00"
}
```

**Error Response (500)**:
```json
{
  "status": "failed",
  "identity": "Managed Identity",
  "workspace": "4cf1706d-4493-45ae-853e-3b87cf6ace86",
  "exceptionType": "HttpResponseError",
  "error": "Access to workspace 'law-nsp-poc' from '20.11.107.220' is denied by Network Security Perimeter",
  "nspError": {
    "code": "NspValidationFailedError",
    "message": "Access was denied by Network Security Perimeter validation."
  },
  "sourceIP": "20.11.107.220",
  "timestamp": "2024-01-15T10:30:00+00:00"
}
```

### `GET /health`

Health check endpoint for Azure Container Apps monitoring and auto-restart functionality.

**Response (200)**:
```json
{
  "status": "healthy",
  "workspace": "4cf1706d-4493-45ae-853e-3b87cf6ace86"
}
```

## Configuration

All configuration is managed through environment variables for secure, flexible deployment:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LOG_ANALYTICS_WORKSPACE_ID` | **Yes** | - | Azure Log Analytics Workspace UUID |
| `WORKSPACE_NAME` | No | `law-nsp-poc` | Display name for the workspace |
| `NSP_SERVICE_TAG` | No | `ContainerAppsManagement.AustraliaEast` | Azure service tag for NSP rules |

### Environment Variable Setup

**Production (Container Apps)**:
Set environment variables through Azure CLI or Azure Portal:
```bash
az containerapp env create \
  --env-vars LOG_ANALYTICS_WORKSPACE_ID="your-workspace-id"
```

## Docker Build

### Standard Build

```bash
docker build \
  -t azure-nsp-analyzer:latest .
```

### Build with Specific Workspace ID

```bash
docker build \
  --build-arg LOG_ANALYTICS_WORKSPACE_ID="your-workspace-id" \
  -t azure-nsp-analyzer:latest .
```

### Image Details

- **Base Image**: `python:3.11-slim` (minimal, secure)
- **Size**: ~450MB (optimized with slim variant)
- **Security**: Runs as non-root user (appuser, uid 1000)
- **Health Checks**: Automatic via HEALTHCHECK directive
- **Port**: 8080 (configurable via container app settings)

## Project Structure

```
.
├── app.py                 # Flask application with NSP dashboard and API
├── Dockerfile            # Multi-stage Docker image (slim, secure)
├── requirements.txt      # Python dependencies with pinned versions
├── .env.example         # Environment variable template (commit this)
├── .env                 # Local environment (git-ignored, never commit)
├── .gitignore          # Git ignore rules (protects .env)
└── README.md           # This file
```

## Key Features Explained

### Network Security Perimeter Integration
- Demonstrates real-world NSP implementation with Log Analytics workspaces
- Shows both success (200) and NSP-blocked (500) scenarios
- Extracts source IP from NSP error messages for debugging

### Managed Identity Authentication
- Uses `DefaultAzureCredential` from azure-identity library
- No secrets stored in code or configuration
- Works seamlessly in Azure Container Apps

### Interactive Dashboard
- Search records in real-time
- View record details in modal dialog
- See Kusto query used for transparency
- Visual architecture diagram showing request flow

### Production-Ready Docker
- Multi-stage build for minimal size (~450MB)
- Non-root user for security
- Health checks for auto-restart
- Unbuffered logging for real-time Container Apps logs

## Contributing

This is a demonstration project for Azure NSP patterns. Feel free to:
- Report issues via GitHub Issues
- Suggest improvements via Discussions
- Fork and adapt for your own use cases

## License

This project is provided as-is for Azure demonstration and educational purposes.

## Support & Documentation

For detailed information on related Azure services:

- **Azure Network Security Perimeter**: [Learn NSP Concepts](https://learn.microsoft.com/en-us/azure/network-security-perimeter/)
- **Azure Container Apps**: [Container Apps Docs](https://learn.microsoft.com/en-us/azure/container-apps/)
- **Azure Log Analytics**: [Monitor Documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/)
- **Kusto Query Language**: [KQL Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- **Azure Managed Identity**: [Identity Documentation](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)

## Author

Hashim's NSP Analysis Tool - [GitHub](https://github.com/HashimsGitHub/Azure-NSP-Analyzer)
