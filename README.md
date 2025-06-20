# JFrog Port Integration

A Python-based integration that synchronizes JFrog Artifactory and Xray data with Port's developer portal, providing comprehensive visibility into repositories, builds, projects, container images, and security vulnerabilities.

## 🚀 Overview

This integration automatically imports and maintains the following entities in Port:

- **JFrog Repositories** - Artifactory repositories with metadata
- **JFrog Builds** - Build information and artifacts  
- **JFrog Projects** - Project configurations and access controls
- **Container Images** - Docker images from repositories
- **Container Vulnerabilities** - Security vulnerabilities detected by Xray
- **Base Image Vulnerabilities** - Vulnerabilities in base container images

## 📋 Prerequisites

- Python 3.7+
- JFrog Artifactory with Xray integration
- Port account with API access
- JFrog Access Token with appropriate permissions

## 🛠️ Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd jfrog-port-integration
```

2. **Install dependencies**
```bash
pip install python-dotenv requests
```

3. **Environment Configuration**

Create a `.env` file in the project root:

```env
# Port Configuration
PORT_CLIENT_ID=your_port_client_id
PORT_CLIENT_SECRET=your_port_client_secret

# JFrog Configuration  
JFROG_ACCESS_TOKEN=your_jfrog_access_token
JFROG_HOST_URL=https://your-instance.jfrog.io
```

## 🏗️ Port Blueprint Setup

Before running the integration, you need to create the following blueprints in Port using the provided JSON schema files:

### Required Blueprints

1. **JFrog Project** (`jfrog-projects.json`)
   - Represents JFrog projects with roles and permissions

2. **Container Vulnerability** (`jfrog-container-vulns.json`)  
   - Tracks vulnerabilities found in container images
   - Includes CVE details, severity levels, and remediation status

3. **Base Image Vulnerability** (`jfrog-baseimage-vulns.json`)
   - Tracks vulnerabilities in base container images
   - Specialized for base image layer analysis

### Blueprint Import

Import each blueprint JSON file through the Port UI:
1. Navigate to your Port instance
2. Go to Builder → Blueprints
3. Click "Create Blueprint" → "Import from JSON"
4. Upload each JSON file

## 🔧 Configuration Files

### Blueprint Schema Files

| File | Description |
|------|-------------|
| `jfrog-projects.json` | Schema for JFrog project entities with roles and admin privileges |
| `jfrog-container-vulns.json` | Schema for container vulnerability tracking with CVE, severity, and status |
| `jfrog-baseimage-vulns.json` | Schema for base image vulnerabilities with layer-specific details |

### Script Files

| File | Description |
|------|-------------|
| `jfrog-script.py` | Main integration script that syncs all JFrog data to Port |

## 🚀 Usage

### Running the Integration

Execute the main script to perform a full synchronization:

```bash
python jfrog-script.py
```

### What the Script Does

1. **Repositories Sync** - Imports all Artifactory repositories with metadata
2. **Builds Sync** - Imports build information and artifacts
3. **Projects Sync** - Imports projects with roles and permissions  
4. **Container Images Sync** - Discovers and imports Docker images
5. **Vulnerability Scan** - Scans images and imports security findings

### Integration Flow

```mermaid
graph TD
    A[Start Integration] --> B[Fetch JFrog Repositories]
    B --> C[Fetch JFrog Builds]
    C --> D[Fetch JFrog Projects]
    D --> E[Discover Container Images]
    E --> F[Scan for Vulnerabilities]
    F --> G[Sync to Port]
    G --> H[Integration Complete]
```

## 📊 Data Mapping

### Repository Properties
- `key` - Repository identifier
- `type` - Repository type (LOCAL, REMOTE, VIRTUAL)
- `packageType` - Package type (Docker, Maven, etc.)
- `url` - Repository URL

### Container Vulnerability Properties
- `cve` - CVE identifier
- `severity` - Critical, High, Medium, Low, Informational, Unknown
- `status` - Open, Fixed, Ignored, Not Applicable
- `component` - Affected package/component
- `imageName` - Full container image name
- `cvssScore` - CVSS vulnerability score

### Base Image Vulnerability Properties
- `cve` - CVE identifier  
- `baseImage` - Base image name (ubuntu, alpine, etc.)
- `layer` - Container layer information
- `fixedVersion` - Version that resolves the vulnerability

## 🔍 Monitoring & Logging

The script provides detailed logging for monitoring the integration:

- **INFO** - General progress and successful operations
- **WARNING** - Non-critical issues (missing data, skipped items)
- **ERROR** - Failed operations and exceptions

Example log output:
```
INFO:__main__:Starting Port integration
INFO:__main__:Getting all repositories
INFO:__main__:Added repository: docker-local
INFO:__main__:Getting vulnerabilities for component: docker-local/app:latest
```

## 🛡️ Security Considerations

- Store sensitive credentials in `.env` file (never commit to version control)
- Use JFrog access tokens with minimal required permissions
- Regularly rotate access tokens
- Monitor API usage and rate limits

## 🔧 Customization

### Modifying Blueprints

To customize the data model:

1. Edit the relevant JSON schema file
2. Update the blueprint in Port
3. Modify the corresponding transformation functions in `jfrog-script.py`

### Adding New Data Sources

To integrate additional JFrog data:

1. Add new API calls to fetch the data
2. Create transformation functions
3. Define new blueprints in Port
4. Add entity creation logic to the main script

## 📝 Troubleshooting

### Common Issues

**Authentication Errors**
- Verify JFrog access token has correct permissions
- Check Port client credentials are valid

**Missing Vulnerabilities**
- Ensure Xray is properly configured and scanning
- Verify container images are accessible

**API Rate Limits**
- Add delays between API calls if needed
- Consider implementing exponential backoff

### Debug Mode

Enable detailed logging by modifying the logging level:

```python
logging.basicConfig(level=logging.DEBUG)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

[Add your license information here]

## 🆘 Support

For issues and questions:
- Check the troubleshooting section
- Review JFrog and Port API documentation
- Create an issue in this repository
