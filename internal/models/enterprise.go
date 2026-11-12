package models

import "time"

type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	Email        *string    `json:"email"`
	FullName     *string    `json:"full_name"`
	PasswordHash string     `json:"-"`
	GlobalRole   string     `json:"global_role"`
	IsActive     bool       `json:"is_active"`
	AvatarURL    *string    `json:"avatar_url"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLogin    *time.Time `json:"last_login"`
}

type ProductType struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description *string   `json:"description"`
	CreatedBy   *int64    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

type Product struct {
	ID                  int64     `json:"id"`
	ProductTypeID       *int64    `json:"product_type_id"`
	Name                string    `json:"name"`
	Description         *string   `json:"description"`
	RepoURL             *string   `json:"repo_url"`
	Lifecycle           string    `json:"lifecycle"`
	Origin              string    `json:"origin"`
	BusinessCriticality string    `json:"business_criticality"`
	Platform            *string   `json:"platform"`
	TechStack           *string   `json:"tech_stack"`
	SLACritical         int       `json:"sla_critical"`
	SLAHigh             int       `json:"sla_high"`
	SLAMedium           int       `json:"sla_medium"`
	SLALow              int       `json:"sla_low"`
	CreatedBy           *int64    `json:"created_by"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type Engagement struct {
	ID             int64      `json:"id"`
	ProductID      int64      `json:"product_id"`
	Name           string     `json:"name"`
	Description    *string    `json:"description"`
	ScanPath       *string    `json:"scan_path"`
	EngagementType string     `json:"engagement_type"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"started_at"`
	CompletedAt    *time.Time `json:"completed_at"`
	TargetStart    *time.Time `json:"target_start"`
	TargetEnd      *time.Time `json:"target_end"`
	TriggeredBy    *int64     `json:"triggered_by"`
	BuildID        *string    `json:"build_id"`
	Branch         *string    `json:"branch"`
	CommitHash     *string    `json:"commit_hash"`
	ScannerVersion *string    `json:"scanner_version"`
}

type Finding struct {
	ID                    int64      `json:"id"`
	EngagementID          int64      `json:"engagement_id"`
	ProductID             *int64     `json:"product_id"`
	RuleID                string     `json:"rule_id"`
	Title                 string     `json:"title"`
	Severity              string     `json:"severity"`
	CVSSScore             *float64   `json:"cvss_score"`
	CVEID                 *string    `json:"cve_id"`
	CWEID                 *string    `json:"cwe_id"`
	FilePath              *string    `json:"file_path"`
	LineNumber            *int       `json:"line_number"`
	ColNumber             *int       `json:"col_number"`
	CodeSnippet           *string    `json:"code_snippet"`
	Description           *string    `json:"description"`
	Impact                *string    `json:"impact"`
	FixSuggestion         *string    `json:"fix_suggestion"`
	References            *string    `json:"references"`
	HashCode              *string    `json:"hash_code"`
	IsDuplicate           bool       `json:"is_duplicate"`
	DuplicateOf           *int64     `json:"duplicate_of"`
	Status                string     `json:"status"`
	KanbanColumn          string     `json:"kanban_column"`
	SLADeadline           *time.Time `json:"sla_deadline"`
	SLABreached           bool       `json:"sla_breached"`
	RiskAccepted          bool       `json:"risk_accepted"`
	RiskAcceptedBy        *int64     `json:"risk_accepted_by"`
	RiskAcceptedReason    *string    `json:"risk_accepted_reason"`
	RiskAcceptedExpiry    *time.Time `json:"risk_accepted_expiry"`
	AssignedTo            *int64     `json:"assigned_to"`
	IsVerified            bool       `json:"is_verified"`
	VerifiedBy            *int64     `json:"verified_by"`
	VerifiedAt            *time.Time `json:"verified_at"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	ResolvedAt            *time.Time `json:"resolved_at"`
	ResolvedBy            *int64     `json:"resolved_by"`
	IsFalsePositive       bool       `json:"is_false_positive"`
	FPReason              *string    `json:"fp_reason"`
	Stack                 string     `json:"stack"`
	AITriageStatus        *string    `json:"ai_triage_status"`
	AITriageSummary       *string    `json:"ai_triage_summary"`
	AgentPrompt           *string    `json:"agent_prompt"`
	AgentPromptAt         *time.Time `json:"agent_prompt_generated_at"`
	VerificationStatus    *string    `json:"verification_status"`
	VerificationSummary   *string    `json:"verification_summary"`
	VerificationLastRunAt *time.Time `json:"verification_last_run_at"`
}

type RunwaySession struct {
	ID              int64     `json:"id"`
	ProductID       int64     `json:"product_id"`
	Status          string    `json:"status"`
	CurrentStep     int       `json:"current_step"`
	ProgressMessage *string   `json:"progress_message"`
	AutoMode        bool      `json:"auto_mode"`
	ThreatModel     *string   `json:"threat_model"`
	SecurityPlan    *string   `json:"security_plan"`
	Remediation     *string   `json:"remediation"`
	PoC             *string   `json:"poc"`
	AuditReport     *string   `json:"audit_report"`
	ScanCountBefore int       `json:"scan_count_before"`
	ScanCountAfter  int       `json:"scan_count_after"`
	ErrorMessage    *string   `json:"error_message"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type AuditLog struct {
	ID         int64     `json:"id"`
	UserID     *int64    `json:"user_id"`
	Username   *string   `json:"username"`
	Action     string    `json:"action"`
	EntityType *string   `json:"entity_type"`
	EntityID   *int64    `json:"entity_id"`
	OldValue   *string   `json:"old_value"`
	NewValue   *string   `json:"new_value"`
	IPAddress  *string   `json:"ip_address"`
	UserAgent  *string   `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
}

type Notification struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Title     string    `json:"title"`
	Body      *string   `json:"body"`
	Type      string    `json:"type"`
	IsRead    bool      `json:"is_read"`
	Link      *string   `json:"link"`
	CreatedAt time.Time `json:"created_at"`
}
