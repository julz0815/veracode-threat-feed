// Types for Phylum Threat Feed API
export interface PhylumThreatPackage {
  created: string;
  ecosystem: string;
  hashes: Array<{
    archive: string;
    hash: string;
    type: string;
  }> | null;
  indicators: Record<string, any>;
  name: string;
  version: string;
}

export interface PhylumThreatFeedResponse {
  has_next: boolean;
  has_previous: boolean;
  packages: PhylumThreatPackage[];
  cursor?: number;
}

// Types for Veracode SCA API
export interface VeracodeWorkspace {
  id: string;
  name: string;
  created: string;
  lastUpdated: string;
}

export interface VeracodeProject {
  id: string;
  name: string;
  workspaceId: string;
  created: string;
  lastUpdated: string;
}

export interface VeracodeLibrary {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  license: string;
  vulnerabilities: any[];
}

export interface VeracodeLibrariesResponse {
  _embedded: {
    libraries: VeracodeLibrary[];
  };
  page: {
    size: number;
    totalElements: number;
    totalPages: number;
    number: number;
  };
}

export interface VeracodeWorkspacesResponse {
  _embedded: {
    workspaces: VeracodeWorkspace[];
  };
}

export interface VeracodeProjectsResponse {
  _embedded: {
    projects: VeracodeProject[];
  };
  page: {
    size: number;
    totalElements: number;
    totalPages: number;
    number: number;
  };
}

// Vulnerable package match
export interface VulnerableMatch {
  threatPackage: PhylumThreatPackage;
  library: VeracodeLibrary;
  project: VeracodeProject;
  workspace: VeracodeWorkspace;
}
