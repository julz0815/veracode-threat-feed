import * as core from '@actions/core';
import * as fs from 'fs';
import axios from 'axios';
import { calculateAuthorizationHeader } from './auth';
import {
  PhylumThreatPackage,
  PhylumThreatFeedResponse,
  VeracodeWorkspace,
  VeracodeProject,
  VeracodeLibrary,
  VeracodeLibrariesResponse,
  VeracodeWorkspacesResponse,
  VeracodeProjectsResponse,
  VulnerableMatch
} from './types';

class ThreatFeedChecker {
  private phylumApiToken: string;
  private veracodeApiId: string;
  private veracodeApiKey: string;
  private veracodeBaseUrl = 'https://api.veracode.com/srcclr/v3';
  private debug: boolean;

  constructor(phylumApiToken: string, veracodeApiId: string, veracodeApiKey: string, debug: boolean = false) {
    this.phylumApiToken = phylumApiToken;
    this.veracodeApiId = veracodeApiId;
    this.veracodeApiKey = veracodeApiKey;
    this.debug = debug;
  }

  private debugLog(message: string, data?: any): void {
    if (this.debug) {
      core.info(`[DEBUG] ${message}`);
      if (data) {
        core.info(`[DEBUG] Data: ${JSON.stringify(data, null, 2)}`);
      }
    }
  }

  async fetchAllThreatPackages(): Promise<PhylumThreatPackage[]> {
    core.info('Fetching all threat packages from Phylum...');
    const allPackages: PhylumThreatPackage[] = [];
    let cursor: number | undefined;
    let hasMore = true;
    let requestCount = 0;

    this.debugLog('Starting Phylum API requests', {
      tokenPrefix: this.phylumApiToken.substring(0, 10),
      tokenLength: this.phylumApiToken.length
    });

    while (hasMore) {
      try {
        requestCount++;
        const url = cursor 
          ? `https://threats.phylum.io/?cursor=${cursor}&per_page=50`
          : 'https://threats.phylum.io/?per_page=50';
        
        core.info(`Making request ${requestCount} to: ${url}`);
        this.debugLog(`Request ${requestCount} details`, {
          url,
          cursor,
          hasMore,
          totalPackagesSoFar: allPackages.length
        });
        
        const startTime = Date.now();
        const response = await axios.get<PhylumThreatFeedResponse>(url, {
          headers: {
            'Authorization': `Bearer ${this.phylumApiToken}`,
            'Content-Type': 'application/json'
          },
          timeout: 30000 // 30 second timeout
        });
        const endTime = Date.now();

        this.debugLog(`Request ${requestCount} completed`, {
          status: response.status,
          responseTime: `${endTime - startTime}ms`,
          responseHeaders: response.headers,
          responseDataKeys: Object.keys(response.data),
          packagesCount: response.data.packages?.length || 0,
          hasNext: response.data.has_next,
          hasPrevious: response.data.has_previous,
          cursor: response.data.cursor
        });

        allPackages.push(...response.data.packages);
        core.info(`Fetched ${response.data.packages.length} packages (total: ${allPackages.length})`);

        if (response.data.cursor) {
          cursor = response.data.cursor;
          this.debugLog(`Continuing with cursor: ${cursor}`);
        } else {
          hasMore = false;
          this.debugLog('No more pages available');
        }
      } catch (error: any) {
        this.debugLog(`Request ${requestCount} failed`, {
          error: error.message,
          status: error.response?.status,
          statusText: error.response?.statusText,
          responseData: error.response?.data,
          responseHeaders: error.response?.headers,
          config: {
            url: error.config?.url,
            method: error.config?.method,
            headers: error.config?.headers
          }
        });
        
        core.error(`Error fetching threat packages (request ${requestCount}): ${error.message}`);
        if (error.response) {
          core.error(`Status: ${error.response.status} - ${error.response.statusText}`);
          core.error(`Response data: ${JSON.stringify(error.response.data)}`);
        }
        throw error;
      }
    }

    core.info(`Total threat packages fetched: ${allPackages.length} in ${requestCount} requests`);
    this.debugLog('Phylum API fetch completed', {
      totalPackages: allPackages.length,
      totalRequests: requestCount
    });
    return allPackages;
  }

  async fetchAllWorkspaces(): Promise<VeracodeWorkspace[]> {
    core.info('Fetching all workspaces from Veracode...');
    
    try {
      const url = '/srcclr/v3/workspaces';
      const fullUrl = `https://api.veracode.com${url}`;
      core.info(`Making request to: ${fullUrl}`);
      core.info(`Using API ID: ${this.veracodeApiId}`);
      
      this.debugLog('Generating Veracode HMAC auth header', {
        apiId: this.veracodeApiId,
        apiKeyLength: this.veracodeApiKey.length,
        host: 'api.veracode.com',
        url: url,
        method: 'GET'
      });
      
      const authHeader = calculateAuthorizationHeader({
        id: this.veracodeApiId,
        key: this.veracodeApiKey,
        host: 'api.veracode.com',
        url: url,
        method: 'GET'
      });
      
      this.debugLog('Generated auth header', {
        authHeader: authHeader.substring(0, 50) + '...',
        authHeaderLength: authHeader.length
      });
      
      const startTime = Date.now();
      const response = await axios.get<VeracodeWorkspacesResponse>(fullUrl, {
        headers: {
          'Authorization': authHeader,
          'Content-Type': 'application/json'
        },
        timeout: 30000 // 30 second timeout
      });
      const endTime = Date.now();

      this.debugLog('Veracode workspaces response', {
        status: response.status,
        responseTime: `${endTime - startTime}ms`,
        responseHeaders: response.headers,
        responseDataKeys: Object.keys(response.data),
        embeddedKeys: response.data._embedded ? Object.keys(response.data._embedded) : 'no _embedded'
      });

      core.info(`Response status: ${response.status}`);
      core.info(`Response data keys: ${Object.keys(response.data)}`);

      const workspaces = response.data._embedded.workspaces;
      core.info(`Fetched ${workspaces.length} workspaces`);
      return workspaces;
    } catch (error: any) {
      this.debugLog('Veracode workspaces request failed', {
        error: error.message,
        status: error.response?.status,
        statusText: error.response?.statusText,
        responseData: error.response?.data,
        responseHeaders: error.response?.headers,
        config: {
          url: error.config?.url,
          method: error.config?.method,
          headers: error.config?.headers
        }
      });
      
      if (error.response) {
        core.error(`Error fetching workspaces: ${error.response.status} - ${error.response.statusText}`);
        core.error(`Response data: ${JSON.stringify(error.response.data)}`);
      } else {
        core.error(`Error fetching workspaces: ${error}`);
      }
      throw error;
    }
  }

  async fetchProjectsForWorkspace(workspaceId: string): Promise<VeracodeProject[]> {
    const allProjects: VeracodeProject[] = [];
    let page = 0;
    let hasMore = true;
    let requestCount = 0;

    this.debugLog(`Starting to fetch projects for workspace ${workspaceId}`);

    while (hasMore) {
      try {
        requestCount++;
        const url = `/srcclr/v3/workspaces/${workspaceId}/projects?page=${page}&size=100`;
        const fullUrl = `https://api.veracode.com${url}`;
        
        this.debugLog(`Fetching projects page ${page} for workspace ${workspaceId}`, {
          url: fullUrl,
          page,
          requestCount
        });
        
        const authHeader = calculateAuthorizationHeader({
          id: this.veracodeApiId,
          key: this.veracodeApiKey,
          host: 'api.veracode.com',
          url: url,
          method: 'GET'
        });
        
        const startTime = Date.now();
        const response = await axios.get<VeracodeProjectsResponse>(fullUrl, {
          headers: {
            'Authorization': authHeader,
            'Content-Type': 'application/json'
          },
          timeout: 30000
        });
        const endTime = Date.now();

        this.debugLog(`Projects page ${page} response`, {
          status: response.status,
          responseTime: `${endTime - startTime}ms`,
          totalElements: response.data.page?.totalElements || 0,
          totalPages: response.data.page?.totalPages || 0,
          currentPage: response.data.page?.number || 0,
          pageSize: response.data.page?.size || 0,
          projectsInThisPage: response.data._embedded?.projects?.length || 0
        });

        if (response.data._embedded?.projects) {
          allProjects.push(...response.data._embedded.projects);
        }

        // Check if there are more pages
        const totalPages = response.data.page?.totalPages || 0;
        const currentPage = response.data.page?.number || 0;
        
        if (currentPage < totalPages - 1) {
          page++;
          this.debugLog(`More pages available, continuing to page ${page}`);
        } else {
          hasMore = false;
          this.debugLog(`No more pages available. Total projects fetched: ${allProjects.length}`);
        }
      } catch (error: any) {
        this.debugLog(`Error fetching projects page ${page} for workspace ${workspaceId}`, {
          error: error.message,
          status: error.response?.status,
          responseData: error.response?.data
        });
        
        core.error(`Error fetching projects for workspace ${workspaceId} (page ${page}): ${error.message}`);
        // Continue to next page or stop if this is the first page
        if (page === 0) {
          return [];
        }
        hasMore = false;
      }
    }

    this.debugLog(`Completed fetching projects for workspace ${workspaceId}`, {
      totalProjects: allProjects.length,
      totalRequests: requestCount
    });

    return allProjects;
  }

  async fetchLibrariesForProject(workspaceId: string, projectId: string): Promise<VeracodeLibrary[]> {
    const allLibraries: VeracodeLibrary[] = [];
    let page = 0;
    let hasMore = true;
    let requestCount = 0;

    this.debugLog(`Starting to fetch libraries for project ${projectId} in workspace ${workspaceId}`);

    while (hasMore) {
      try {
        requestCount++;
        const url = `/srcclr/v3/workspaces/${workspaceId}/projects/${projectId}/libraries?page=${page}&size=100`;
        const fullUrl = `https://api.veracode.com${url}`;
        
        this.debugLog(`Fetching libraries page ${page} for project ${projectId}`, {
          url: fullUrl,
          page,
          requestCount
        });
        
        const authHeader = calculateAuthorizationHeader({
          id: this.veracodeApiId,
          key: this.veracodeApiKey,
          host: 'api.veracode.com',
          url: url,
          method: 'GET'
        });
        
        const startTime = Date.now();
        const response = await axios.get<VeracodeLibrariesResponse>(fullUrl, {
          headers: {
            'Authorization': authHeader,
            'Content-Type': 'application/json'
          },
          timeout: 30000
        });
        const endTime = Date.now();

        this.debugLog(`Libraries page ${page} response`, {
          status: response.status,
          responseTime: `${endTime - startTime}ms`,
          totalElements: response.data.page?.totalElements || 0,
          totalPages: response.data.page?.totalPages || 0,
          currentPage: response.data.page?.number || 0,
          pageSize: response.data.page?.size || 0,
          librariesInThisPage: response.data._embedded?.libraries?.length || 0
        });

        if (response.data._embedded?.libraries) {
          allLibraries.push(...response.data._embedded.libraries);
        }

        // Check if there are more pages
        const totalPages = response.data.page?.totalPages || 0;
        const currentPage = response.data.page?.number || 0;
        
        if (currentPage < totalPages - 1) {
          page++;
          this.debugLog(`More pages available, continuing to page ${page}`);
        } else {
          hasMore = false;
          this.debugLog(`No more pages available. Total libraries fetched: ${allLibraries.length}`);
        }
      } catch (error: any) {
        this.debugLog(`Error fetching libraries page ${page} for project ${projectId}`, {
          error: error.message,
          status: error.response?.status,
          responseData: error.response?.data
        });
        
        core.error(`Error fetching libraries for project ${projectId} in workspace ${workspaceId} (page ${page}): ${error.message}`);
        // Continue to next page or stop if this is the first page
        if (page === 0) {
          return [];
        }
        hasMore = false;
      }
    }

    this.debugLog(`Completed fetching libraries for project ${projectId}`, {
      totalLibraries: allLibraries.length,
      totalRequests: requestCount
    });

    return allLibraries;
  }

  async fetchAllLibraries(): Promise<Array<{ library: VeracodeLibrary; project: VeracodeProject; workspace: VeracodeWorkspace }>> {
    core.info('Fetching all libraries from Veracode...');
    const allLibraries: Array<{ library: VeracodeLibrary; project: VeracodeProject; workspace: VeracodeWorkspace }> = [];
    
    const workspaces = await this.fetchAllWorkspaces();
    
    for (const workspace of workspaces) {
      core.info(`Processing workspace: ${workspace.name} (${workspace.id})`);
      const projects = await this.fetchProjectsForWorkspace(workspace.id);
      
              for (const project of projects) {
          core.info(`  Processing project: ${project.name} (${project.id})`);
          const libraries = await this.fetchLibrariesForProject(workspace.id, project.id);
          
          for (const library of libraries) {
            allLibraries.push({ library, project, workspace });
          }
          
          core.info(`    Found ${libraries.length} libraries in project ${project.name}`);
        }
    }

    core.info(`Total libraries fetched: ${allLibraries.length}`);
    return allLibraries;
  }

  findVulnerableMatches(threatPackages: PhylumThreatPackage[], allLibraries: Array<{ library: VeracodeLibrary; project: VeracodeProject; workspace: VeracodeWorkspace }>): VulnerableMatch[] {
    core.info('Comparing threat packages with project libraries...');
    const matches: VulnerableMatch[] = [];

    for (const threatPackage of threatPackages) {
      for (const { library, project, workspace } of allLibraries) {
        if (threatPackage.name === library.name && threatPackage.version === library.version) {
          matches.push({
            threatPackage,
            library,
            project,
            workspace
          });
        }
      }
    }

    core.info(`Found ${matches.length} vulnerable package matches`);
    return matches;
  }

  generateSummary(matches: VulnerableMatch[]): string {
    let summary = 'THREAT FEED SECURITY ALERT SUMMARY\n';
    summary += '=====================================\n\n';
    summary += `Generated: ${new Date().toISOString()}\n`;
    summary += `Total vulnerable packages found: ${matches.length}\n\n`;

    if (matches.length === 0) {
      summary += '✅ No vulnerable packages found in your projects.\n';
      summary += 'All packages in your Veracode SCA projects are clean.\n';
    } else {
      summary += '🚨 IMMEDIATE ATTENTION REQUIRED!\n';
      summary += 'The following packages in your projects match known threats:\n\n';

      matches.forEach((match, index) => {
        summary += `${index + 1}. Package: ${match.threatPackage.name}@${match.threatPackage.version}\n`;
        summary += `   Ecosystem: ${match.threatPackage.ecosystem}\n`;
        summary += `   Threat Indicators: ${Object.keys(match.threatPackage.indicators).join(', ')}\n`;
        summary += `   Workspace: ${match.workspace.name} (${match.workspace.id})\n`;
        summary += `   Project: ${match.project.name} (${match.project.id})\n`;
        summary += `   Library ID: ${match.library.id}\n`;
        summary += `   Library License: ${match.library.license}\n`;
        summary += `   Threat Created: ${match.threatPackage.created}\n`;
        summary += `   Library Vulnerabilities: ${match.library.vulnerabilities.length}\n`;
        summary += '\n';
      });

      summary += '\n⚠️  ACTION REQUIRED:\n';
      summary += '1. Review the above packages immediately\n';
      summary += '2. Update or remove vulnerable packages\n';
      summary += '3. Check for alternative secure packages\n';
      summary += '4. Run security scans on affected projects\n';
    }

    return summary;
  }

  generateMaliciousPackagesTable(threatPackages: PhylumThreatPackage[]): string {
    let table = 'MALICIOUS PACKAGES FROM THREAT FEED\n';
    table += '=====================================\n\n';
    table += `Generated: ${new Date().toISOString()}\n`;
    table += `Total packages in threat feed: ${threatPackages.length}\n\n`;

    if (threatPackages.length === 0) {
      table += 'No packages found in threat feed.\n';
    } else {
      // Sort packages by creation date (newest first)
      const sortedPackages = [...threatPackages].sort((a, b) => 
        new Date(b.created).getTime() - new Date(a.created).getTime()
      );

      // Calculate column widths for proper alignment
      let maxDateLength = 10; // "Date Added" length
      let maxEcosystemLength = 9; // "Ecosystem" length
      let maxPackageNameLength = 12; // "Package Name" length
      let maxVersionLength = 15; // "Package Version" length

      // Find maximum lengths
      sortedPackages.forEach(pkg => {
        const dateAdded = new Date(pkg.created).toISOString().split('T')[0];
        const ecosystem = pkg.ecosystem || 'Unknown';
        const packageName = pkg.name || 'Unknown';
        const packageVersion = pkg.version || 'Unknown';
        
        maxDateLength = Math.max(maxDateLength, dateAdded.length);
        maxEcosystemLength = Math.max(maxEcosystemLength, ecosystem.length);
        maxPackageNameLength = Math.max(maxPackageNameLength, packageName.length);
        maxVersionLength = Math.max(maxVersionLength, packageVersion.length);
      });

      // Create table header with proper padding
      const header = `| ${'Date Added'.padEnd(maxDateLength)} | ${'Ecosystem'.padEnd(maxEcosystemLength)} | ${'Package Name'.padEnd(maxPackageNameLength)} | ${'Package Version'.padEnd(maxVersionLength)} |\n`;
      const separator = `|${'-'.repeat(maxDateLength + 2)}|${'-'.repeat(maxEcosystemLength + 2)}|${'-'.repeat(maxPackageNameLength + 2)}|${'-'.repeat(maxVersionLength + 2)}|\n`;
      
      table += header;
      table += separator;

      // Add table rows with proper padding
      sortedPackages.forEach(pkg => {
        const dateAdded = new Date(pkg.created).toISOString().split('T')[0];
        const ecosystem = pkg.ecosystem || 'Unknown';
        const packageName = pkg.name || 'Unknown';
        const packageVersion = pkg.version || 'Unknown';
        
        const row = `| ${dateAdded.padEnd(maxDateLength)} | ${ecosystem.padEnd(maxEcosystemLength)} | ${packageName.padEnd(maxPackageNameLength)} | ${packageVersion.padEnd(maxVersionLength)} |\n`;
        table += row;
      });

      table += '\n';
      table += 'Note: This table contains all packages from the Phylum threat feed.\n';
      table += 'Packages that match your project libraries are highlighted in the summary.txt file.\n';
    }

    return table;
  }

  async run(): Promise<void> {
    try {
      // Fetch all threat packages
      const threatPackages = await this.fetchAllThreatPackages();
      
      // Fetch all libraries from all workspaces and projects
      const allLibraries = await this.fetchAllLibraries();
      
      // Find matches
      const matches = this.findVulnerableMatches(threatPackages, allLibraries);
      
      // Generate summary
      const summary = this.generateSummary(matches);
      
      // Generate malicious packages table
      const maliciousPackagesTable = this.generateMaliciousPackagesTable(threatPackages);
      
      // Write files
      fs.writeFileSync('summary.txt', summary);
      fs.writeFileSync('new-malicious-packages.txt', maliciousPackagesTable);
      
      core.info('Summary written to summary.txt');
      core.info('Malicious packages table written to new-malicious-packages.txt');
      
      // Output to console
      console.log(summary);
      
      // Set outputs
      core.setOutput('vulnerable_packages_count', matches.length);
      core.setOutput('summary_file', 'summary.txt');
      core.setOutput('malicious_packages_file', 'new-malicious-packages.txt');
      
      if (matches.length > 0) {
        core.setFailed(`Found ${matches.length} vulnerable packages that require immediate attention!`);
        process.exit(1);
      } else {
        core.info('✅ No vulnerable packages found. All clear!');
        process.exit(0);
      }
      
    } catch (error) {
      core.error(`Action failed: ${error}`);
      core.setFailed(`Action failed: ${error}`);
      process.exit(1);
    }
  }
}

function getRequiredInput(name: string, envVarName: string): string {
  // First try GitHub Action input
  const actionInput = core.getInput(name, { required: false });
  if (actionInput) {
    return actionInput;
  }

  // Then try environment variable
  const envValue = process.env[envVarName];
  if (envValue) {
    return envValue;
  }

  // If neither exists, throw an error
  throw new Error(
    `Missing required parameter '${name}'. ` +
    `Please provide it as a GitHub Action input or set the environment variable '${envVarName}'. ` +
    `For local testing, you can set: export ${envVarName}='your-value'`
  );
}

function validateInputs(): { phylumApiToken: string; veracodeApiId: string; veracodeApiKey: string; debug: boolean } {
  try {
    const phylumApiToken = getRequiredInput('phylum_api_token', 'PHYLUM_API_TOKEN');
    const veracodeApiId = getRequiredInput('veracode_api_id', 'VERACODE_API_ID');
    const veracodeApiKey = getRequiredInput('veracode_api_key', 'VERACODE_API_KEY');
    
    // Debug flag - try action input first, then env var, default to false
    const debugActionInput = core.getInput('debug', { required: false });
    const debugEnvVar = process.env.DEBUG;
    const debug = debugActionInput === 'true' || debugEnvVar === 'true';

    // Validate token formats
    if (phylumApiToken && !phylumApiToken.startsWith('ph0_') && !phylumApiToken.startsWith('p0_')) {
      core.warning('Phylum API token should start with "ph0_" or "p0_". Please verify your token is correct.');
    }

    if (veracodeApiId && veracodeApiId.length < 20) {
      core.warning('Veracode API ID seems too short. Please verify your API ID is correct.');
    }

    if (veracodeApiKey && veracodeApiKey.length < 50) {
      core.warning('Veracode API Key seems too short. Please verify your API key is correct.');
    }

    core.info('✅ All required parameters validated successfully');
    core.info(`📋 Configuration:`);
    core.info(`   - Phylum API Token: ${phylumApiToken.substring(0, 10)}...`);
    core.info(`   - Veracode API ID: ${veracodeApiId}`);
    core.info(`   - Veracode API Key: ${veracodeApiKey.substring(0, 10)}...`);
    core.info(`   - Debug Mode: ${debug ? 'Enabled' : 'Disabled'}`);

    return { phylumApiToken, veracodeApiId, veracodeApiKey, debug };
  } catch (error: any) {
    core.setFailed(`Input validation failed: ${error.message}`);
    throw error;
  }
}

async function run(): Promise<void> {
  try {
    // Validate all required inputs
    const { phylumApiToken, veracodeApiId, veracodeApiKey, debug } = validateInputs();

    if (debug) {
      core.info('🐛 Debug mode enabled - detailed logging will be shown');
    }

    const checker = new ThreatFeedChecker(phylumApiToken, veracodeApiId, veracodeApiKey, debug);
    await checker.run();
  } catch (error: any) {
    core.setFailed(`Action failed during initialization: ${error.message}`);
    process.exit(1);
  }
}

// Run the action
if (require.main === module) {
  run().catch((error) => {
    core.setFailed(`Action failed: ${error}`);
    process.exit(1);
  });
}

export { ThreatFeedChecker };
