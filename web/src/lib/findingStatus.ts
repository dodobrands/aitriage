import type { Finding } from '../types';

type StatusFinding = Pick<Finding, 'status'> & Partial<Pick<Finding, 'verification_status'>>;
export const resolvedStatuses = ['resolved', 'fixed', 'closed', 'mitigated'];
export const suppressedStatuses = ['false_positive', 'risk_accepted', 'accepted_risk'];
export const terminalStatuses = [...resolvedStatuses, ...suppressedStatuses];

export function findingStatus(f: StatusFinding): string {
  const status = f.status?.toLowerCase().trim() || 'open';
  if (status === 'open' && f.verification_status === 'fixed') return 'resolved';
  if (status === 'fixed') return 'resolved';
  if (status === 'accepted_risk') return 'risk_accepted';
  return status;
}
export const isResolved = (f: StatusFinding) => resolvedStatuses.includes(findingStatus(f));
export const isSuppressed = (f: StatusFinding) => suppressedStatuses.includes(findingStatus(f));
export const isActive = (f: StatusFinding) => !terminalStatuses.includes(findingStatus(f));
export function severityCounts(findings: Finding[]) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings.filter(isActive)) {
    const severity = f.severity.toLowerCase() as keyof typeof counts;
    if (severity in counts) counts[severity]++;
  }
  return counts;
}
