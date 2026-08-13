export const NAVIGATION_GATE_BOOTSTRAP_RULE_ID = 73_100;
export const NAVIGATION_GATE_REDIRECT_RULE_ID = 73_101;
export const NAVIGATION_GATE_ALLOW_RULE_ID = 73_102;
export const MAX_NAVIGATION_GATE_TARGET_BYTES = 8_192;

const MAIN_FRAME_GET_CONDITION = Object.freeze({
  regexFilter: "^(https?://.*)$",
  isUrlFilterCaseSensitive: false,
  resourceTypes: ["main_frame"],
  requestMethods: ["get"]
});

export function navigationGateRedirectRule(waitPageUrl) {
  if (typeof waitPageUrl !== "string" || !waitPageUrl.startsWith("chrome-extension://")) {
    throw new Error("navigation gate wait page must be an extension URL");
  }
  return {
    id: 73_101,
    priority: 2,
    action: {
      type: "redirect",
      redirect: {
        regexSubstitution: `${waitPageUrl}#\\1`
      }
    },
    condition: { ...MAIN_FRAME_GET_CONDITION }
  };
}

export function navigationGateAllowRule() {
  return {
    id: NAVIGATION_GATE_ALLOW_RULE_ID,
    priority: 3,
    action: { type: "allow" },
    condition: { ...MAIN_FRAME_GET_CONDITION }
  };
}

export function validNavigationGateTarget(candidate) {
  if (
    typeof candidate !== "string" ||
    candidate.length === 0 ||
    utf8Length(candidate) > MAX_NAVIGATION_GATE_TARGET_BYTES
  ) {
    return null;
  }
  try {
    const target = new URL(candidate);
    const href = target.href;
    if (
      (target.protocol !== "http:" && target.protocol !== "https:") ||
      target.username !== "" ||
      target.password !== "" ||
      utf8Length(href) > MAX_NAVIGATION_GATE_TARGET_BYTES
    ) {
      return null;
    }
    return href;
  } catch {
    return null;
  }
}

function utf8Length(value) {
  try {
    return encodeURIComponent(value).replace(/%[0-9A-F]{2}|./gi, "x").length;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

export function navigationGateRuntimeReady(
  status,
  nowUnixSeconds = Math.floor(Date.now() / 1000)
) {
  const validUntil = status?.headerSync?.targetEvidenceValidUntilUnix;
  return Boolean(
    status &&
      status.state === "active" &&
      status.proxyActive === true &&
      status.headerSync?.treeRootReady === true &&
      status.headerSync?.blocksUntilAuthoritativeTreeRoot === 0 &&
      status.headerSync?.targetEvidenceExpired === false &&
      Number.isSafeInteger(validUntil) &&
      validUntil > nowUnixSeconds
  );
}

export class NavigationGateController {
  constructor({
    updateDynamicRules,
    updateSessionRules,
    waitPageUrl,
    isCurrent,
    now = () => Date.now(),
    runtimeReady = navigationGateRuntimeReady
  }) {
    this.updateDynamicRules = updateDynamicRules;
    this.updateSessionRules = updateSessionRules;
    this.redirectRule = navigationGateRedirectRule(waitPageUrl);
    this.isCurrent = isCurrent;
    this.now = now;
    this.runtimeReady = runtimeReady;
    this.queue = Promise.resolve();
    this.openConfirmed = false;
    this.openSequence = 0;
    this.openRevision = null;
  }

  close(expectedControlEpoch) {
    return this.#enqueue(expectedControlEpoch, async () => {
      this.openConfirmed = false;
      this.openRevision = null;
      // Removing the higher-priority session allow is the physical close
      // boundary. The lower-priority redirect is an enabled packaged rule, so
      // it already exists before this worker starts or an update runs.
      await this.updateSessionRules({
        removeRuleIds: [NAVIGATION_GATE_ALLOW_RULE_ID]
      });
      this.#requireCurrent(expectedControlEpoch);
      // Repair the higher-priority exact-target redirect after the physical
      // close. Until this finishes, the enabled static bootstrap redirect
      // still holds navigation on the generic wait page.
      await this.updateDynamicRules({
        removeRuleIds: [NAVIGATION_GATE_REDIRECT_RULE_ID],
        addRules: [this.redirectRule]
      });
      this.#requireCurrent(expectedControlEpoch);
      this.openConfirmed = false;
      this.openRevision = null;
      return null;
    });
  }

  open(expectedControlEpoch) {
    return this.#enqueue(expectedControlEpoch, async () => {
      if (this.openConfirmed) return this.openRevision;
      await this.updateDynamicRules({
        removeRuleIds: [NAVIGATION_GATE_REDIRECT_RULE_ID],
        addRules: [this.redirectRule]
      });
      this.#requireCurrent(expectedControlEpoch);
      await this.updateSessionRules({
        removeRuleIds: [NAVIGATION_GATE_ALLOW_RULE_ID],
        addRules: [navigationGateAllowRule()]
      });
      this.#requireCurrent(expectedControlEpoch);
      this.openSequence += 1;
      this.openRevision = `${this.now()}-${this.openSequence}`;
      this.openConfirmed = true;
      return this.openRevision;
    });
  }

  status(runtimeStatus) {
    const ready =
      this.openConfirmed &&
      this.runtimeReady(runtimeStatus, Math.floor(this.now() / 1000));
    return Object.freeze({
      schemaVersion: 1,
      ready,
      openRevision: ready ? this.openRevision : null
    });
  }

  logicallyOpen(runtimeStatus) {
    return (
      this.openConfirmed &&
      this.runtimeReady(runtimeStatus, Math.floor(this.now() / 1000))
    );
  }

  #enqueue(expectedControlEpoch, operation) {
    const result = this.queue.then(() => {
      this.#requireCurrent(expectedControlEpoch);
      return operation();
    });
    this.queue = result.catch(() => {});
    return result;
  }

  #requireCurrent(expectedControlEpoch) {
    if (!this.isCurrent(expectedControlEpoch)) {
      const error = new Error("navigation gate control generation was superseded");
      error.code = "controlEpochSuperseded";
      throw error;
    }
  }
}
