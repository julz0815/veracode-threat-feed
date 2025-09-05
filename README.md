# Threat Feed Security Check Action

A GitHub Action that checks for vulnerable packages by comparing Phylum's threat feed with your Veracode SCA project libraries.

## Features

- 🔍 Fetches all packages from Phylum's threat feed API
- 🏢 Retrieves all workspaces, projects, and libraries from Veracode SCA
- ⚖️ Compares package names and versions to find matches
- 📝 Generates detailed summary report
- 🚨 Fails the pipeline if vulnerable packages are found
- 📊 Provides comprehensive vulnerability information

## Usage

### GitHub Actions

#### Basic Usage

```yaml
name: Security Check
on: [workflow_dispatch]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Threat Feed Check
        uses: ./
        with:
          phylum_api_token: ${{ secrets.PHYLUM_API_TOKEN }}
          veracode_api_id: ${{ secrets.VERACODE_API_ID }}
          veracode_api_key: ${{ secrets.VERACODE_API_KEY }}
```

#### Scheduled Usage

```yaml
name: Weekly Security Check
on:
  schedule:
    - cron: '0 9 * * 1' # Every Monday at 9 AM UTC

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Threat Feed Check
        uses: ./
        with:
          phylum_api_token: ${{ secrets.PHYLUM_API_TOKEN }}
          veracode_api_id: ${{ secrets.VERACODE_API_ID }}
          veracode_api_key: ${{ secrets.VERACODE_API_KEY }}
          debug: 'true'
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security-check

variables:
  # Set these in GitLab CI/CD Settings > Variables
  # PHYLUM_API_TOKEN: Your Phylum API token
  # VERACODE_API_ID: Your Veracode API ID  
  # VERACODE_API_KEY: Your Veracode API Key

threat-feed-check:
  stage: security-check
  image: node:18-alpine
  before_script:
    - apk add --no-cache git
    - git clone https://github.com/your-username/threat-feed-action.git action
    - cd action
  script:
    - node dist/index.js
  artifacts:
    when: always
    paths:
      - action/summary.txt
      - action/new-malicious-packages.txt
    expire_in: 30 days
```

### Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
- main
- develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  # Set these in Azure DevOps > Pipelines > Library > Variable Groups
  # PHYLUM_API_TOKEN: Your Phylum API token
  # VERACODE_API_ID: Your Veracode API ID
  # VERACODE_API_KEY: Your Veracode API Key

stages:
- stage: SecurityCheck
  displayName: 'Threat Feed Security Check'
  jobs:
  - job: ThreatFeedCheck
    displayName: 'Check for Vulnerable Packages'
    steps:
    - checkout: self
    - script: |
        git clone https://github.com/your-username/threat-feed-action.git action
        cd action
      displayName: 'Setup Threat Feed Action'
    - script: |
        cd action
        node dist/index.js
      displayName: 'Run Threat Feed Check'
      env:
        PHYLUM_API_TOKEN: $(PHYLUM_API_TOKEN)
        VERACODE_API_ID: $(VERACODE_API_ID)
        VERACODE_API_KEY: $(VERACODE_API_KEY)
        DEBUG: 'true'
    - task: PublishBuildArtifacts@1
      inputs:
        pathToPublish: 'action'
        artifactName: 'security-reports'
      condition: always()
```

### Local Execution

The action can be run locally for testing and development purposes.

#### Prerequisites

1. **Node.js** (version 18 or higher)
2. **npm** (comes with Node.js)
3. **Your API credentials**

> **Note**: The `dist/index.js` file is included in the repository, so no build step is required for CI/CD pipelines.

#### Method 1: Environment Variables (Recommended)

```bash
# Set your API credentials
export PHYLUM_API_TOKEN='ph0_your-actual-token'
export VERACODE_API_ID='your-veracode-api-id'
export VERACODE_API_KEY='your-veracode-api-key'
export DEBUG='true'  # Optional: Enable debug logging

# Build and run
npm run build
node dist/index.js
```

#### Method 2: GitHub Action Input Format

```bash
# Set credentials using GitHub Action input format
export INPUT_PHYLUM_API_TOKEN='ph0_your-actual-token'
export INPUT_VERACODE_API_ID='your-veracode-api-id'
export INPUT_VERACODE_API_KEY='your-veracode-api-key'
export INPUT_DEBUG='true'  # Optional: Enable debug logging

# Build and run
npm run build
node dist/index.js
```

#### Method 3: Inline Environment Variables

```bash
# Run with inline environment variables
PHYLUM_API_TOKEN='ph0_your-token' \
VERACODE_API_ID='your-id' \
VERACODE_API_KEY='your-key' \
DEBUG='true' \
node dist/index.js
```

#### Local Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run tests
npm test

# Run locally with your credentials
export PHYLUM_API_TOKEN='your-token'
export VERACODE_API_ID='your-id'
export VERACODE_API_KEY='your-key'
node dist/index.js
```

## Inputs

| Input | Description | Required |
|-------|-------------|----------|
| `phylum_api_token` | Your Phylum API token | Yes |
| `veracode_api_id` | Your Veracode API ID | Yes |
| `veracode_api_key` | Your Veracode API Key | Yes |

## Outputs

| Output | Description |
|--------|-------------|
| `vulnerable_packages_count` | Number of vulnerable packages found |
| `summary_file` | Path to the generated summary file |
| `malicious_packages_file` | Path to the generated malicious packages table file |

## Setup

### 1. Get Phylum API Token

1. Sign up for a Phylum account at [phylum.io](https://phylum.io)
2. Navigate to your API settings
3. Generate a new API token (should start with `ph0_` or `p0_`)
4. Add it to your CI/CD platform (see platform-specific instructions below)

### 2. Get Veracode API Credentials

1. Log in to your Veracode account
2. Go to Settings > API Credentials
3. Create new API credentials
4. Add them to your CI/CD platform (see platform-specific instructions below)

### 3. Platform-Specific Setup

#### GitHub Actions

1. Go to your repository settings
2. Navigate to Secrets and variables > Actions
3. Add the following secrets:
   - `PHYLUM_API_TOKEN`
   - `VERACODE_API_ID`
   - `VERACODE_API_KEY`

#### GitLab CI

1. Go to your project's CI/CD settings
2. Navigate to Variables
3. Add the following variables (mark as protected/masked as needed):
   - `PHYLUM_API_TOKEN`
   - `VERACODE_API_ID`
   - `VERACODE_API_KEY`

#### Azure DevOps

1. Go to your project's Pipelines
2. Navigate to Library > Variable Groups
3. Create a new variable group with:
   - `PHYLUM_API_TOKEN`
   - `VERACODE_API_ID`
   - `VERACODE_API_KEY`
4. Link the variable group to your pipeline

#### Jenkins

1. Go to Jenkins > Manage Jenkins > Credentials
2. Add the following credentials (mark as secret as needed):
   - `phylum-api-token` (Secret text)
   - `veracode-api-id` (Secret text)
   - `veracode-api-key` (Secret text)
3. Use the Jenkinsfile provided in the repository

#### Local Development

Set environment variables in your shell:
```bash
export PHYLUM_API_TOKEN='ph0_your-actual-token'
export VERACODE_API_ID='your-veracode-api-id'
export VERACODE_API_KEY='your-veracode-api-key'
```

## Supported CI/CD Platforms

This action supports multiple CI/CD platforms:

| Platform | Status | Features |
|----------|--------|----------|
| **GitHub Actions** | ✅ Native | Full integration, secrets management, artifacts |
| **GitLab CI** | ✅ Supported | Environment variables, artifacts, reports |
| **Azure DevOps** | ✅ Supported | Variable groups, build artifacts, test results |
| **Jenkins** | ✅ Supported | Credentials management, build artifacts, test results |
| **Local Execution** | ✅ Supported | Development, testing, debugging |

### Platform Comparison

#### GitHub Actions
- **Best for**: GitHub-hosted repositories
- **Features**: Native integration, built-in secrets, automatic artifacts
- **Setup**: Repository secrets in Settings > Actions

#### GitLab CI
- **Best for**: GitLab-hosted repositories
- **Features**: Environment variables, protected variables, artifacts
- **Setup**: Project variables in CI/CD settings

#### Azure DevOps
- **Best for**: Microsoft ecosystem, enterprise environments
- **Features**: Variable groups, build artifacts, test result publishing
- **Setup**: Variable groups in Pipelines > Library

#### Jenkins
- **Best for**: Self-hosted CI/CD, enterprise environments
- **Features**: Credentials management, build artifacts, test result publishing
- **Setup**: Credentials in Jenkins > Manage Jenkins > Credentials

#### Local Execution
- **Best for**: Development, testing, debugging
- **Features**: Full debug logging, flexible configuration
- **Setup**: Environment variables in your shell

## How It Works

1. **Fetch Threat Data**: Retrieves all packages from Phylum's threat feed using cursor-based pagination
2. **Fetch Project Data**: Gets all workspaces, then all projects per workspace, then all libraries per project from Veracode SCA
3. **Compare Packages**: Matches package names and versions between threat feed and project libraries
4. **Generate Report**: Creates a detailed summary of any matches found
5. **Fail Pipeline**: If vulnerable packages are found, the action fails with exit code 1

## Output

The action generates two files:

### `summary.txt`
Contains detailed security analysis:
- Total count of vulnerable packages found
- Detailed information for each match including:
  - Package name and version
  - Threat indicators
  - Workspace and project information
  - Library details
  - Vulnerability count
- Action recommendations

### `new-malicious-packages.txt`
Contains a table of all packages from the Phylum threat feed:
- Date Added (YYYY-MM-DD format)
- Ecosystem (npm, PyPI, etc.)
- Package Name
- Package Version
- Sorted by creation date (newest first)

## Example Output

```
THREAT FEED SECURITY ALERT SUMMARY
=====================================

Generated: 2024-01-15T10:30:00.000Z
Total vulnerable packages found: 2

🚨 IMMEDIATE ATTENTION REQUIRED!
The following packages in your projects match known threats:

1. Package: malicious-package@1.0.0
   Ecosystem: npm
   Threat Indicators: npm_hooks_rule, suspicious_url_references_rule
   Workspace: My Workspace (ws-123)
   Project: My Project (proj-456)
   Library ID: lib-789
   Library License: MIT
   Threat Created: Mon, 15 Jan 2024 00:00:00 GMT
   Library Vulnerabilities: 3

⚠️  ACTION REQUIRED:
1. Review the above packages immediately
2. Update or remove vulnerable packages
3. Check for alternative secure packages
4. Run security scans on affected projects
```

## Troubleshooting

### Common Issues

#### 1. Missing Required Parameters
```
Error: Missing required parameter 'phylum_api_token'
```
**Solution**: Set the required environment variables:
```bash
export PHYLUM_API_TOKEN='your-token'
export VERACODE_API_ID='your-id'
export VERACODE_API_KEY='your-key'
```

#### 2. Invalid API Token Format
```
Warning: Phylum API token should start with "ph0_" or "p0_"
```
**Solution**: Verify your Phylum API token format. It should start with `ph0_` or `p0_`.

#### 3. API Authentication Failed
```
Error: Request failed with status code 401
```
**Solution**: 
- Verify your API credentials are correct
- Check that your tokens haven't expired
- Ensure you have the right permissions

#### 4. No Workspaces Found
```
Error: No workspaces found in Veracode
```
**Solution**:
- Verify your Veracode API credentials
- Check that you have access to workspaces
- Ensure your Veracode account has SCA enabled

#### 5. Network/Timeout Issues
```
Error: socket hang up
```
**Solution**:
- Check your internet connection
- Verify API endpoints are accessible
- Try running with debug mode enabled

### Debug Mode

Enable debug mode for detailed logging:
```bash
export DEBUG='true'
node dist/index.js
```

This will show:
- Detailed API request/response information
- Pagination progress
- Error details
- Performance metrics

### Local Development

```bash
# For development, install dependencies and build
npm install
npm run build

# For production use, the dist/index.js is already built
# Just run with your credentials:
export DEBUG='true'
export PHYLUM_API_TOKEN='your-token'
export VERACODE_API_ID='your-id'
export VERACODE_API_KEY='your-key'
node dist/index.js
```

## Development

### Building

```bash
npm install
npm run build
```

### Testing

```bash
npm test
```

## License

MIT
