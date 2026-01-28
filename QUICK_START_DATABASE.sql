-- ============================================================================
-- EURA 2.0 Database Schema - Quick Start
-- Run this FIRST if your tables don't exist yet
-- ============================================================================
-- 
-- This creates all tables from scratch
-- Safe to run even if some tables exist (uses IF NOT EXISTS)
--
-- Run this in Supabase SQL Editor
-- ============================================================================

-- Enable UUIDs
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- Create all tables
-- ============================================================================

-- Organizations
CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Projects
CREATE TABLE IF NOT EXISTS projects (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_scan_at TIMESTAMP WITH TIME ZONE,
  last_scan_id UUID
);

-- Repositories
CREATE TABLE IF NOT EXISTS repositories (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  provider VARCHAR(50) NOT NULL CHECK (provider IN ('github', 'gitlab', 'bitbucket', 'azure_devops')),
  owner VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  url TEXT NOT NULL,
  default_branch VARCHAR(255) DEFAULT 'main',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  CONSTRAINT repositories_provider_owner_name_unique UNIQUE(provider, owner, name)
);

-- Scans
CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
  status VARCHAR(50) NOT NULL CHECK (status IN ('queued', 'processing', 'completed', 'failed')),
  repo_name VARCHAR(255) NOT NULL,
  commit_hash VARCHAR(40),
  installation_id BIGINT,
  total_files INTEGER,
  analyzed_files INTEGER,
  duration_ms INTEGER,
  error TEXT,
  verdict VARCHAR(20) CHECK (verdict IN ('SHIP_ALLOWED', 'SHIP_BLOCKED')),
  raw_results JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  completed_at TIMESTAMP WITH TIME ZONE
);

-- Rules
CREATE TABLE IF NOT EXISTS rules (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  rule_id VARCHAR(50) UNIQUE NOT NULL,
  version VARCHAR(20) NOT NULL DEFAULT '0.1',
  regulation VARCHAR(50) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description_short TEXT,
  description_long TEXT,
  severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  is_blocking BOOLEAN DEFAULT false,
  rule_definition JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Rule Results
CREATE TABLE IF NOT EXISTS rule_results (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  rule_id VARCHAR(50) REFERENCES rules(rule_id) ON DELETE CASCADE,
  status VARCHAR(20) NOT NULL CHECK (status IN ('PASS', 'FAIL', 'UNKNOWN', 'NOT_APPLICABLE')),
  confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
  reason TEXT,
  evidence JSONB,
  evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  CONSTRAINT rule_results_scan_rule_unique UNIQUE(scan_id, rule_id)
);

-- Scan Dependencies
CREATE TABLE IF NOT EXISTS scan_dependencies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  version VARCHAR(100),
  type VARCHAR(50),
  file_source VARCHAR(255),
  license VARCHAR(100),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Findings
CREATE TABLE IF NOT EXISTS findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  category VARCHAR(50) NOT NULL,
  title VARCHAR(255) NOT NULL,
  summary TEXT,
  details TEXT,
  file_path VARCHAR(500),
  line_number INTEGER,
  code_snippet TEXT,
  recommendation TEXT,
  confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
  fingerprint VARCHAR(64) UNIQUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Compliance Reports
CREATE TABLE IF NOT EXISTS compliance_reports (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  regulation VARCHAR(50) NOT NULL,
  verdict VARCHAR(20) NOT NULL CHECK (verdict IN ('SHIP_ALLOWED', 'SHIP_BLOCKED')),
  score DECIMAL(5,2) CHECK (score >= 0 AND score <= 100),
  total_rules INTEGER,
  passed INTEGER,
  failed INTEGER,
  unknown INTEGER,
  not_applicable INTEGER,
  evaluated_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  CONSTRAINT compliance_reports_scan_regulation_unique UNIQUE(scan_id, regulation)
);

-- Compliance Details
CREATE TABLE IF NOT EXISTS compliance_details (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  report_id UUID REFERENCES compliance_reports(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  rule_id VARCHAR(50) REFERENCES rules(rule_id) ON DELETE CASCADE,
  status VARCHAR(20) NOT NULL CHECK (status IN ('PASS', 'FAIL', 'UNKNOWN', 'NOT_APPLICABLE')),
  confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
  reason TEXT,
  evaluated_at TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT compliance_details_report_rule_unique UNIQUE(report_id, rule_id)
);

-- AI Systems
CREATE TABLE IF NOT EXISTS ai_systems (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
  name VARCHAR(255),
  classification VARCHAR(50) CHECK (classification IN ('prohibited', 'high_risk', 'limited_risk', 'minimal_risk', 'unknown')),
  frameworks TEXT[],
  use_case TEXT,
  confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
  detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Model Cards
CREATE TABLE IF NOT EXISTS model_cards (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  ai_system_id UUID REFERENCES ai_systems(id) ON DELETE CASCADE,
  file_path VARCHAR(500),
  content JSONB,
  validation_status VARCHAR(20) CHECK (validation_status IN ('valid', 'invalid', 'incomplete', 'not_found')),
  validation_errors TEXT[],
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Create indexes
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans(project_id) WHERE project_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scans_repository_id ON scans(repository_id) WHERE repository_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rule_results_scan_id ON rule_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_rule_results_rule_id ON rule_results(rule_id);
CREATE INDEX IF NOT EXISTS idx_scan_dependencies_scan_id ON scan_dependencies(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_scan_id ON compliance_reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_repositories_project_id ON repositories(project_id);
CREATE INDEX IF NOT EXISTS idx_projects_organization_id ON projects(organization_id);

-- ============================================================================
-- Create triggers for updated_at
-- ============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_organizations_updated_at ON organizations;
CREATE TRIGGER update_organizations_updated_at 
  BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_projects_updated_at ON projects;
CREATE TRIGGER update_projects_updated_at 
  BEFORE UPDATE ON projects FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_repositories_updated_at ON repositories;
CREATE TRIGGER update_repositories_updated_at 
  BEFORE UPDATE ON repositories FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_rules_updated_at ON rules;
CREATE TRIGGER update_rules_updated_at 
  BEFORE UPDATE ON rules FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Enable RLS
-- ============================================================================

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_dependencies ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_details ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_systems ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_cards ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- Done! Schema created successfully.
-- ============================================================================
