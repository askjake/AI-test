(function (root, factory) {
  "use strict";
  const value = factory();
  if (typeof module === "object" && module.exports) module.exports = value;
  else root.WatchLearnLifecycle = value;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  function evidenceIdentity(session) {
    if (!session || !Array.isArray(session.evidence)) return null;
    for (let index = session.evidence.length - 1; index >= 0; index -= 1) {
      const item = session.evidence[index];
      if (item && item.access_state === "available") {
        return {
          sessionId: String(session.session_id),
          evidenceId: String(item.evidence_id),
          revision: String(item.sha256),
          width: Number(item.width),
          height: Number(item.height),
          record: item,
        };
      }
    }
    return null;
  }

  function sameEvidence(left, right) {
    return Boolean(
      left && right &&
      left.sessionId === right.sessionId &&
      left.evidenceId === right.evidenceId &&
      left.revision === right.revision &&
      left.width === right.width &&
      left.height === right.height
    );
  }

  class FrameCoordinator {
    constructor() {
      this.sessionId = null;
      this.appliedVersion = 0;
      this.generation = 0;
      this.token = 0;
      this.bound = null;
      this.pending = null;
    }

    select(session) {
      const sessionId = String(session && session.session_id || "");
      const version = Number(session && session.version || 0);
      if (this.sessionId === sessionId && version < this.appliedVersion) {
        return {kind: "ignored", reason: "out_of_order", version};
      }
      if (this.sessionId !== sessionId) {
        this.sessionId = sessionId;
        this.appliedVersion = 0;
        this.bound = null;
        this.pending = null;
        this.token += 1;
      }
      this.appliedVersion = Math.max(this.appliedVersion, version);
      const identity = evidenceIdentity(session);
      if (!identity) {
        this.pending = null;
        this.bound = null;
        this.token += 1;
        return {kind: "empty", token: this.token};
      }
      if (sameEvidence(this.bound, identity)) {
        this.bound.record = identity.record;
        return {kind: "same", binding: this.binding()};
      }
      if (sameEvidence(this.pending, identity)) {
        this.pending.record = identity.record;
        return {kind: "waiting", token: this.pending.token, identity: this.pending};
      }
      this.token += 1;
      this.pending = {...identity, token: this.token};
      return {kind: "load", token: this.token, identity: this.pending};
    }

    commit(token, naturalWidth, naturalHeight) {
      if (!this.pending || this.pending.token !== token) {
        return {kind: "obsolete"};
      }
      if (
        Number(naturalWidth) !== this.pending.width ||
        Number(naturalHeight) !== this.pending.height
      ) {
        this.pending = null;
        return {kind: "invalid_dimensions"};
      }
      this.generation += 1;
      this.bound = {...this.pending, generation: this.generation};
      this.pending = null;
      return {kind: "committed", binding: this.binding()};
    }

    fail(token) {
      if (!this.pending || this.pending.token !== token) return false;
      this.pending = null;
      return true;
    }

    binding() {
      if (!this.bound) return null;
      return Object.freeze({
        sessionId: this.bound.sessionId,
        evidenceId: this.bound.evidenceId,
        revision: this.bound.revision,
        width: this.bound.width,
        height: this.bound.height,
        generation: this.bound.generation,
      });
    }

    isCurrent(binding) {
      const current = this.binding();
      return Boolean(
        current && binding &&
        current.sessionId === binding.sessionId &&
        current.evidenceId === binding.evidenceId &&
        current.revision === binding.revision &&
        current.width === binding.width &&
        current.height === binding.height &&
        current.generation === binding.generation
      );
    }
  }

  function partitionObsolete(queue, coordinator, invalidateCurrent) {
    const keep = [];
    const disposable = [];
    const meaningful = [];
    for (const item of queue) {
      if (!item.canvasBinding || (!invalidateCurrent && coordinator.isCurrent(item.canvasBinding))) keep.push(item);
      else if (item.disposable) disposable.push(item);
      else meaningful.push(item);
    }
    return {keep, disposable, meaningful};
  }

  return Object.freeze({FrameCoordinator, evidenceIdentity, sameEvidence, partitionObsolete});
});
