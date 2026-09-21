/**
 * Deciding what a background poll is allowed to do with a Runway session.
 *
 * The dashboard polls for the latest session every few seconds so a run started
 * in another tab, or finished while the browser was closed, still shows up. That
 * poll used to restore *any* session it found and force the panel open —
 * including one that had already completed. Starting a new audit therefore
 * bounced back to the previous, finished one within seconds.
 *
 * The rule: a live run may always claim the screen, because that is what the
 * operator is waiting for. A finished run may only update the view when the
 * operator has not taken control, or when it is the very run already on screen.
 */

export type RunwayStatus = string | null | undefined;

export interface RestoreDecision {
  /** Whether the polled session should be written into the view at all. */
  apply: boolean;
  /** Whether it may also open the Runway panel and pull focus. */
  takeOver: boolean;
}

export interface RestoreInput {
  /** Status reported by the backend for the polled session. */
  status: RunwayStatus;
  /** Id of the polled session. */
  sessionId: number | null | undefined;
  /** Id of the session currently displayed, if any. */
  onScreenSessionId: number | null | undefined;
  /** True once the operator has deliberately started or dismissed a run. */
  userDriven: boolean;
}

/** A run that is still executing, in either spelling the backend uses. */
export const isLiveStatus = (status: RunwayStatus): boolean => {
  const normalized = String(status ?? '').toLowerCase();
  return normalized === 'running' || normalized === 'in_progress';
};

/** A run that has reached a terminal state and is therefore history. */
export const isFinishedStatus = (status: RunwayStatus): boolean => {
  const normalized = String(status ?? '').toLowerCase();
  return normalized === 'completed' || normalized === 'failed';
};

export const decideRestore = ({
  status,
  sessionId,
  onScreenSessionId,
  userDriven,
}: RestoreInput): RestoreDecision => {
  const live = isLiveStatus(status);
  const sameSession = sessionId != null && sessionId === onScreenSessionId;

  // Before the operator does anything, restoring the last session is helpful:
  // it is how a completed run survives a page reload.
  if (!userDriven) {
    return { apply: true, takeOver: true };
  }

  // A live run is always worth showing — it is the thing being waited on.
  if (live) {
    return { apply: true, takeOver: true };
  }

  // Otherwise only the run already on screen may update, and it may not grab
  // focus: the operator has moved on.
  return { apply: sameSession, takeOver: false };
};
