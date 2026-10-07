import { describe, it, expect } from 'vitest';
import { isActive, isResolved, isSuppressed, findingStatus } from './findingStatus';

describe('finding lifecycle', () => {
  it.each(['resolved', 'fixed', 'closed', 'mitigated', 'RESOLVED'])('counts %s as resolved, not active or suppressed', status => {
    const f = { status };
    expect(isResolved(f)).toBe(true); expect(isActive(f)).toBe(false); expect(isSuppressed(f)).toBe(false);
  });
  it.each(['triage', 'open', 'pending_verification', 'verification_failed', 'sent_to_agent', 'confirmed'])('keeps %s active', status => expect(isActive({ status })).toBe(true));
  it('aligns historical verification results and accepted risk aliases', () => {
    expect(findingStatus({ status: 'open', verification_status: 'fixed' })).toBe('resolved');
    expect(isSuppressed({ status: 'accepted_risk' })).toBe(true);
  });
});
