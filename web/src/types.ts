export type Tab =
  | 'dashboard'
  | 'browser'
  | 'audit'
  | 'admin'
  | 'dependencies'
  | 'chat'
  | 'triage'
  | 'products'
  | 'engagements';

export interface User {
  id: number;
  username: string;
  email: string;
  full_name: string;
  global_role: string;
  is_admin: boolean;
}

export type ScanStatusValue = 'idle' | 'scanning' | 'done' | 'complete' | 'error';

export interface RecentScan {
  status: string;
  project: string;
  findings_count: number;
  files_count: number;
  stack?: string;
  timestamp?: string;
}

export interface Finding {
  id: number;
  engagement_id: number;
  product_id?: number;
  rule_id: string;
  title: string;
  severity: string;
  cvss_score?: number;
  cve_id?: string;
  cwe_id?: string;
  file_path?: string;
  line_number?: number;
  col_number?: number;
  code_snippet?: string;
  description?: string;
  impact?: string;
  fix_suggestion?: string;
  references?: string;
  hash_code?: string;
  is_duplicate: boolean;
  duplicate_of?: number;
  status: string;
  kanban_column: string;
  sla_deadline?: string;
  sla_breached: boolean;
  risk_accepted: boolean;
  risk_accepted_by?: number;
  risk_accepted_reason?: string;
  risk_accepted_expiry?: string;
  assigned_to?: number;
  is_verified: boolean;
  verified_by?: number;
  verified_at?: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  resolved_by?: number;
  is_false_positive: boolean;
  fp_reason?: string;
  stack: string;
  ai_triage_status?: 'true_positive' | 'false_positive' | 'needs_review';
  ai_triage_summary?: string;
  agent_prompt?: string;
  agent_prompt_generated_at?: string;
  verification_status?: 'running' | 'fixed' | 'not_fixed' | 'error';
  verification_summary?: string;
  verification_last_run_at?: string;
  // Legacy properties
  audit_status?: string;
  ai_analysis?: string;
  file?: string;
  owasp?: string;
  suggestion?: string;
}

// Aligned with Go scanResponse (server.go:150-160)
export interface ScanReport {
  ok: boolean;
  scan_id: string;
  findings: Finding[];
  dependencies: Dependency[];
  stacks: string[];
  security_score: number;
  security_grade: string;
  health_check?: HealthCheckResult;
  duration: string;
  error?: string;
}

export interface HealthCheckResult {
  score: number;
  grade: string;
  has_critical_failures: boolean;
  breakdown: HealthCheckBreakdown;
  policy?: HealthCheckPolicy;
  verdict?: HealthCheckVerdict;
}

export interface HealthCheckBreakdown {
  base_score: number;
  penalty: number;
  bonus: number;
  raw_weight: number;
  active_findings: number;
  ignored_findings: number;
  deduped_findings: number;
  penalty_by_source: Record<string, number>;
  count_by_severity: Record<string, number>;
  count_by_source?: Record<string, number>;
  count_by_class?: Record<string, number>;
}

export interface HealthCheckPolicy {
  profile: string;
  fail_on: string;
  minimum_score: number;
  max_critical: number;
  max_high: number;
  max_medium: number;
  block_sources?: string[];
  block_classes?: string[];
}

export interface HealthCheckVerdict {
  passed: boolean;
  status: string;
  summary: string;
  blocking_reasons?: HealthCheckBlockingReason[];
}

export interface HealthCheckBlockingReason {
  code: string;
  message: string;
  severity?: string;
  source?: string;
  class?: string;
  count?: number;
  threshold?: number;
}

// Aligned with Go deps.Dependency
export interface Dependency {
  name: string;
  version: string;
  type: string;
  ecosystem: string;
}

export interface HealthStatus {
  ok: boolean;
  tools: Record<string, boolean>;
}

export interface AdminUser {
  username: string;
  is_admin: boolean;
}

export interface Product {
  id: number;
  product_type_id?: number;
  name: string;
  description?: string;
  repo_url?: string;
  lifecycle: string;
  origin: string;
  business_criticality: string;
  platform?: string;
  tech_stack?: string;
  sla_critical: number;
  sla_high: number;
  sla_medium: number;
  sla_low: number;
  created_by?: number;
  created_at: string;
  updated_at: string;
}

export interface ProductType {
  id: number;
  name: string;
  description?: string;
  created_by?: number;
  created_at: string;
}

export interface Engagement {
  id: string;
  product_id: string;
  name: string;
  status: string;
  start_date: string;
  end_date?: string;
}
