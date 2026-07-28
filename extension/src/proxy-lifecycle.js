import { headerSyncReadyForProxyActivation } from "./header-status.js";

export const BLOCKING_PAC_SCRIPT =
  'function FindProxyForURL(url, host) { return "PROXY 127.0.0.1:1"; }';

export class SerializedMandatoryPacController {
  constructor(
    setPac,
    readPac,
    controlEpochIsCurrent,
    confirmationTimeoutMs = 2000
  ) {
    if (
      typeof setPac !== "function" ||
      typeof readPac !== "function" ||
      typeof controlEpochIsCurrent !== "function"
    ) {
      throw new TypeError("PAC controller actions must be functions");
    }
    if (
      !Number.isSafeInteger(confirmationTimeoutMs) ||
      confirmationTimeoutMs < 1
    ) {
      throw new TypeError("PAC confirmation timeout must be positive");
    }
    this.setPac = setPac;
    this.readPac = readPac;
    this.controlEpochIsCurrent = controlEpochIsCurrent;
    this.confirmationTimeoutMs = confirmationTimeoutMs;
    this.tail = Promise.resolve();
    this.desired = null;
    this.mutationRevision = 0;
  }

  install(pacScript, expectedControlEpoch) {
    if (
      typeof pacScript !== "string" ||
      !pacScript.includes("FindProxyForURL")
    ) {
      return Promise.reject(new TypeError("PAC script is invalid"));
    }
    try {
      this.requireCurrent(expectedControlEpoch);
    } catch (error) {
      return Promise.reject(error);
    }
    if (this.mutationRevision >= Number.MAX_SAFE_INTEGER) {
      return Promise.reject(new Error("PAC mutation revision is exhausted"));
    }
    const mutationRevision = ++this.mutationRevision;
    this.desired = {
      pacScript,
      expectedControlEpoch,
      mutationRevision
    };
    const operation = this.tail
      .catch(() => {})
      .then(async () => {
        this.requireCurrent(expectedControlEpoch);
        const mutation = Promise.resolve().then(() => this.setPac(pacScript));
        const outcome = await Promise.race([
          mutation.then(() => "confirmed"),
          delay(this.confirmationTimeoutMs).then(() => "timeout")
        ]);
        if (outcome === "timeout") {
          const observed = await Promise.race([
            Promise.resolve()
              .then(() => this.readPac())
              .then(
                (value) => ({ completed: true, value }),
                () => ({ completed: false, value: null })
              ),
            delay(this.confirmationTimeoutMs).then(() => ({
              completed: false,
              value: null
            }))
          ]);
          if (!observed.completed || observed.value !== pacScript) {
            mutation.then(
              () => this.repairAfterLateMutation(mutationRevision),
              () => {}
            );
            const error = new Error(
              "mandatory PAC mutation could not be confirmed"
            );
            error.code = "proxyMutationUnconfirmed";
            throw error;
          }
        }
        this.requireCurrent(expectedControlEpoch);
      });
    this.tail = operation.catch(() => {});
    return operation;
  }

  requireCurrent(expectedControlEpoch) {
    if (!this.controlEpochIsCurrent(expectedControlEpoch)) {
      const error = new Error("proxy control generation was superseded");
      error.code = "controlEpochSuperseded";
      throw error;
    }
  }

  repairAfterLateMutation(completedMutationRevision) {
    const desired = this.desired;
    if (
      desired == null ||
      desired.mutationRevision === completedMutationRevision ||
      !this.controlEpochIsCurrent(desired.expectedControlEpoch)
    ) {
      return;
    }
    void this.install(
      desired.pacScript,
      desired.expectedControlEpoch
    ).catch(() => {});
  }
}

export class SerializedEpochMutationController {
  constructor(epochIsCurrent) {
    if (typeof epochIsCurrent !== "function") {
      throw new TypeError("epoch guard must be a function");
    }
    this.epochIsCurrent = epochIsCurrent;
    this.tail = Promise.resolve();
  }

  run(expectedEpoch, mutation) {
    if (typeof mutation !== "function") {
      return Promise.reject(new TypeError("epoch mutation must be a function"));
    }
    try {
      this.requireCurrent(expectedEpoch);
    } catch (error) {
      return Promise.reject(error);
    }
    const operation = this.tail
      .catch(() => {})
      .then(async () => {
        this.requireCurrent(expectedEpoch);
        const result = await mutation();
        this.requireCurrent(expectedEpoch);
        return result;
      });
    this.tail = operation.catch(() => {});
    return operation;
  }

  requireCurrent(expectedEpoch) {
    if (!this.epochIsCurrent(expectedEpoch)) {
      const error = new Error("proxy control generation was superseded");
      error.code = "controlEpochSuperseded";
      throw error;
    }
  }
}

export async function settleLifecycleBarrier(operation) {
  if (operation == null || typeof operation.then !== "function") return;
  try {
    await operation;
  } catch {
    // A settled failure may be retried by the replacement generation.
  }
}

export async function deactivateIfHeaderEvidenceExpired(
  candidate,
  deactivate,
  nowUnixSeconds = Math.floor(Date.now() / 1000)
) {
  if (typeof deactivate !== "function") {
    throw new TypeError("header expiry deactivation must be a function");
  }
  if (headerSyncReadyForProxyActivation(candidate, nowUnixSeconds)) {
    return false;
  }
  await deactivate();
  return true;
}

export function headerReadinessFailClosed(candidate) {
  return (
    candidate != null &&
    candidate.state === "degraded" &&
    candidate.reason === "headerReadinessUnavailable" &&
    candidate.proxyActive === true
  );
}

export async function installPacForCurrentNativeGeneration(
  installPac,
  nativeGenerationIsCurrent,
  publishActivation
) {
  if (
    typeof installPac !== "function" ||
    typeof nativeGenerationIsCurrent !== "function" ||
    typeof publishActivation !== "function"
  ) {
    throw new TypeError("proxy activation actions must be functions");
  }
  await installPac();
  if (!nativeGenerationIsCurrent()) {
    throw new Error("native host generation changed during PAC activation");
  }
  return publishActivation();
}

export function sameLiveProxyGeneration(expected, current) {
  const expectedLive =
    expected?.state === "active" || headerReadinessFailClosed(expected);
  const currentLive =
    current?.state === "active" || headerReadinessFailClosed(current);
  return (
    expectedLive &&
    currentLive &&
    current.state === expected.state &&
    current.reason === expected.reason &&
    expected.proxyActive === true &&
    current.proxyActive === true &&
    typeof expected.runtimeSession === "string" &&
    current.runtimeSession === expected.runtimeSession &&
    Number.isSafeInteger(expected.runtimeGeneration) &&
    current.runtimeGeneration === expected.runtimeGeneration &&
    Number.isSafeInteger(expected.policyGeneration) &&
    current.policyGeneration === expected.policyGeneration &&
    Number.isSafeInteger(expected.securityMaintenanceEpoch) &&
    current.securityMaintenanceEpoch === expected.securityMaintenanceEpoch
  );
}

export function runtimeControlToken(
  controlEpoch,
  connectionEpoch,
  candidate
) {
  if (
    !Number.isSafeInteger(controlEpoch) ||
    controlEpoch < 1 ||
    !Number.isSafeInteger(connectionEpoch) ||
    connectionEpoch < 1 ||
    typeof candidate?.runtimeSession !== "string" ||
    !Number.isSafeInteger(candidate.runtimeGeneration) ||
    !Number.isSafeInteger(candidate.policyGeneration)
  ) {
    return null;
  }
  return Object.freeze({
    controlEpoch,
    connectionEpoch,
    runtimeSession: candidate.runtimeSession,
    runtimeGeneration: candidate.runtimeGeneration,
    policyGeneration: candidate.policyGeneration
  });
}

export function runtimeControlTokenIsCurrent(
  expected,
  currentControlEpoch,
  currentConnectionEpoch,
  candidate
) {
  return (
    expected != null &&
    expected.controlEpoch === currentControlEpoch &&
    expected.connectionEpoch === currentConnectionEpoch &&
    candidate?.runtimeSession === expected.runtimeSession &&
    candidate.runtimeGeneration === expected.runtimeGeneration &&
    candidate.policyGeneration === expected.policyGeneration
  );
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
