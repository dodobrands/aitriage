import { describe, it, expect } from 'vitest';
import { decideRestore, isFinishedStatus, isLiveStatus } from './runwayRestore';

// A pilot user reported: "Нельзя запустить новый аудит из раздела отчётов,
// просто кидает в раздел Обзор и показывает старый аудит." The 5-second poller
// restored the last completed session and forced its panel open, overwriting
// whatever the operator had just started.

describe('decideRestore', () => {
  it('restores the last session on a fresh page, so a finished run survives a reload', () => {
    expect(
      decideRestore({ status: 'completed', sessionId: 7, onScreenSessionId: null, userDriven: false }),
    ).toEqual({ apply: true, takeOver: true });
  });

  it('does not pull the operator back to a finished session once they are driving', () => {
    const decision = decideRestore({
      status: 'completed',
      sessionId: 7,
      onScreenSessionId: 9,
      userDriven: true,
    });

    expect(decision.apply).toBe(false);
    expect(decision.takeOver).toBe(false);
  });

  it('does not resurrect a dismissed session when nothing is on screen', () => {
    // "Run again" clears the session; the next poll must not undo that.
    const decision = decideRestore({
      status: 'completed',
      sessionId: 7,
      onScreenSessionId: null,
      userDriven: true,
    });

    expect(decision.apply).toBe(false);
  });

  it('keeps updating the finished session the operator is actually looking at', () => {
    const decision = decideRestore({
      status: 'completed',
      sessionId: 7,
      onScreenSessionId: 7,
      userDriven: true,
    });

    expect(decision.apply).toBe(true);
    // It may refresh in place, but must not re-open or steal focus.
    expect(decision.takeOver).toBe(false);
  });

  it('always shows a live run, because that is what the operator is waiting for', () => {
    for (const status of ['running', 'in_progress', 'RUNNING']) {
      expect(
        decideRestore({ status, sessionId: 12, onScreenSessionId: 3, userDriven: true }),
      ).toEqual({ apply: true, takeOver: true });
    }
  });

  it('treats a failed run as history, not as something to jump back to', () => {
    const decision = decideRestore({
      status: 'failed',
      sessionId: 4,
      onScreenSessionId: 8,
      userDriven: true,
    });

    expect(decision.apply).toBe(false);
  });
});

describe('status helpers', () => {
  it('recognises both spellings of a live run', () => {
    expect(isLiveStatus('running')).toBe(true);
    expect(isLiveStatus('in_progress')).toBe(true);
    expect(isLiveStatus('completed')).toBe(false);
  });

  it('recognises terminal states', () => {
    expect(isFinishedStatus('completed')).toBe(true);
    expect(isFinishedStatus('failed')).toBe(true);
    expect(isFinishedStatus('running')).toBe(false);
  });

  it('survives a missing status instead of throwing', () => {
    expect(isLiveStatus(undefined)).toBe(false);
    expect(isFinishedStatus(null)).toBe(false);
  });
});
