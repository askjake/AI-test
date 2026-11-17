"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  FrameCoordinator,
  evidenceIdentity,
  partitionObsolete,
  sameEvidence,
} = require("../../static/watch_learn_lifecycle.js");

function session(version, revision, evidenceId = "evidence-a", width = 1280, height = 720) {
  return {
    session_id: "session-1234567890",
    version,
    evidence: [{
      evidence_id: evidenceId,
      sha256: revision,
      width,
      height,
      access_state: "available",
    }],
  };
}

test("same-evidence updates retain one bound generation", () => {
  const coordinator = new FrameCoordinator();
  const selected = coordinator.select(session(3, "a".repeat(64)));
  assert.equal(selected.kind, "load");
  assert.equal(coordinator.commit(selected.token, 1280, 720).kind, "committed");
  const first = coordinator.binding();
  const update = coordinator.select(session(6, "a".repeat(64)));
  assert.equal(update.kind, "same");
  assert.deepEqual(coordinator.binding(), first);
});

test("out-of-order response cannot replace newer session state", () => {
  const coordinator = new FrameCoordinator();
  const first = coordinator.select(session(9, "a".repeat(64)));
  coordinator.commit(first.token, 1280, 720);
  assert.equal(coordinator.select(session(8, "b".repeat(64), "evidence-b")).kind, "ignored");
  assert.equal(coordinator.binding().revision, "a".repeat(64));
});

test("new pixels atomically advance the browser-local generation", () => {
  const coordinator = new FrameCoordinator();
  const frameA = coordinator.select(session(1, "a".repeat(64)));
  coordinator.commit(frameA.token, 1280, 720);
  const bindingA = coordinator.binding();
  const frameB = coordinator.select(session(4, "b".repeat(64), "evidence-b"));
  assert.equal(frameB.kind, "load");
  assert.equal(coordinator.isCurrent(bindingA), true);
  coordinator.commit(frameB.token, 1280, 720);
  assert.equal(coordinator.isCurrent(bindingA), false);
  assert.equal(coordinator.binding().revision, "b".repeat(64));
  assert.equal(coordinator.binding().generation, bindingA.generation + 1);
});

test("dimension mismatch never binds metadata to different pixels", () => {
  const coordinator = new FrameCoordinator();
  const selected = coordinator.select(session(1, "c".repeat(64), "evidence-c", 640, 480));
  assert.equal(coordinator.commit(selected.token, 641, 480).kind, "invalid_dimensions");
  assert.equal(coordinator.binding(), null);
});

test("frame transition separates disposable and meaningful queued input", () => {
  const coordinator = new FrameCoordinator();
  const selected = coordinator.select(session(1, "d".repeat(64)));
  coordinator.commit(selected.token, 1280, 720);
  const binding = coordinator.binding();
  const partition = partitionObsolete([
    {name: "global-control", canvasBinding: null, disposable: false},
    {name: "move", canvasBinding: binding, disposable: true},
    {name: "click", canvasBinding: binding, disposable: false},
  ], coordinator, true);
  assert.deepEqual(partition.keep.map(item => item.name), ["global-control"]);
  assert.deepEqual(partition.disposable.map(item => item.name), ["move"]);
  assert.deepEqual(partition.meaningful.map(item => item.name), ["click"]);
});

test("evidence identity ignores unavailable records and compares every frame field", () => {
  const value = session(1, "e".repeat(64));
  value.evidence.push({...value.evidence[0], evidence_id: "denied", access_state: "redaction_failed"});
  const identity = evidenceIdentity(value);
  assert.equal(identity.evidenceId, "evidence-a");
  assert.equal(sameEvidence(identity, {...identity, width: identity.width + 1}), false);
});
