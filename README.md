# Azure Container App - NSP Security Dashboard

A Flask-based Azure Container App that queries Log Analytics workspaces through Network Security Perimeter (NSP) validation.

## Features

- **Network Security Perimeter Integration**: Demonstrates secure access to protected Log Analytics workspaces
- **Managed Identity Authentication**: Uses Azure Managed Identity for secure authentication
- **Live Syslog Dashboard**: Real-time visualization of Log Analytics Syslog records
- **Security Monitoring**: Tracks NSP validation results and security posture
- **Responsive UI**: Modern, dark-themed web interface

## Prerequisites

- Python 3.8+
- Azure subscription with:
  - Container Apps environment
  - Log Analytics Workspace
  - Network Security Perimeter enabled
- Azure CLI (for local testing)

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/CAE.git
cd CAE
```

### 2. Create Environment Variables

Copy the example file and add your actual workspace ID:

```bash
cp .env.example .env
```

Edit `.env` and add your Log Analytics Workspace ID:

```env
LOG_ANALYTICS_WORKSPACE_ID=4cf1706d-4493-45ae-853e-3b87cf6ace86
WORKSPACE_NAME=law-nsp-poc
NSP_SERVICE_TAG=ContainerAppsManagement.AustraliaEast
```

**Note**: The `.env` file is git-ignored and will NOT be uploaded to GitHub.

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run Locally

```bash
python app.py
```

Visit `http://localhost:8080` in your browser.

### 5. Deploy to Azure Container Apps

```bash
# Build the image
docker build --build-arg LOG_ANALYTICS_WORKSPACE_ID="YOUR_WORKSPACE_ID" -t cae-app:latest .

# Tag for registry
docker tag cae-app:latest YOUR_REGISTRY.azurecr.io/cae-app:latest

# Push to registry
docker push YOUR_REGISTRY.azurecr.io/cae-app:latest

# Deploy to Container Apps (using Azure CLI)
az containerapp create \
  --name cae-app \
  --resource-group YOUR_RG \
  --environment YOUR_ENV \
  --image YOUR_REGISTRY.azurecr.io/cae-app:latest \
  --env-vars LOG_ANALYTICS_WORKSPACE_ID=YOUR_WORKSPACE_ID
```

## API Endpoints

### `GET /`
Returns the HTML dashboard with live Syslog records from the workspace.

**Success Response (200)**:
- Displays connected workspace status
- Shows latest Syslog records
- Displays Kusto query used

**Error Response (500)**:
- Indicates NSP validation failure
- Shows source IP and error details
- Displays security architecture

### `GET /api/status`
JSON API endpoint for programmatic access.

**Request**:
```bash
curl http://localhost:8080/api/status
```

**Success Response (200)**:
```json
{
  "status": "success",
  "identity": "Managed Identity",
  "workspace": "4cf1706d-4493-45ae-853e-3b87cf6ace86",
  "query": "Syslog | where TimeGenerated > ago(24h) | order by TimeGenerated desc | take 5",
  "rowCount": 5,
  "tableCount": 1,
  "sampleRecords": [...],
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
  "error": "Access to workspace 'law-nsp-poc' from '20.11.107.220' is denied",
  "nspError": {
    "code": "NspValidationFailedError",
    "message": "Access was denied by Network Security Perimeter validation."
  },
  "sourceIP": "20.11.107.220",
  "timestamp": "2024-01-15T10:30:00+00:00"
}
```

### `GET /health`
Health check endpoint for monitoring.

**Response (200)**:
```json
{
  "status": "healthy",
  "workspace": "4cf1706d-4493-45ae-853e-3b87cf6ace86"
}
```

## Configuration

All configuration is done via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LOG_ANALYTICS_WORKSPACE_ID` | Yes | - | Azure Log Analytics Workspace ID |
| `WORKSPACE_NAME` | No | `law-nsp-poc` | Display name for the workspace |
| `NSP_SERVICE_TAG` | No | `ContainerAppsManagement.AustraliaEast` | Azure service tag for NSP |

## Docker Build

Build locally with your workspace ID:

```bash
docker build \
  --build-arg LOG_ANALYTICS_WORKSPACE_ID="YOUR_WORKSPACE_ID" \
  -t cae-app:latest .
```

## Troubleshooting

### "LOG_ANALYTICS_WORKSPACE_ID environment variable is not set"

Ensure the environment variable is defined before running:

```bash
export LOG_ANALYTICS_WORKSPACE_ID="your-workspace-id"
python app.py
```

### NSP Validation Failed

Check that:
1. The Managed Identity has Log Analytics Reader permissions
2. The workspace is in a Network Security Perimeter
3. The Container App's service tag is allowed in NSP rules

### Cannot Query Workspace

Verify:
1. Workspace ID is correct (UUID format)
2. Managed Identity has appropriate RBAC roles
3. Log Analytics workspace is accessible from Container App subnet

## Project Structure

```
.
├── app.py                 # Flask application
├── Dockerfile            # Container image definition
├── requirements.txt      # Python dependencies
├── .env.example         # Environment variable template
├── .env                 # Local environment (git-ignored)
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

## Security Notes

- **Never commit `.env` file** - it's in `.gitignore`
- **Use Managed Identity** for Azure authentication (never hardcode credentials)
- **Restrict RBAC** - give Managed Identity minimal required permissions
- **NSP Rules** - ensure only necessary service tags can access the workspace
- **Use environment variables** for all sensitive configuration

## License

This project is provided as-is for Azure demonstration purposes.

## Support

For issues with:
- **Azure NSP**: [Azure Network Security Perimeter Docs](https://learn.microsoft.com/en-us/azure/network-security-perimeter/)
- **Container Apps**: [Azure Container Apps Docs](https://learn.microsoft.com/en-us/azure/container-apps/)
- **Log Analytics**: [Azure Monitor Documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/)# Azure-NSP-Analyzer
Tool to test Azure Network Security Perimeter
