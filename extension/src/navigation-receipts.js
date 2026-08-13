import {
  currentConnectSecurityDecision,
  currentSecurityResult
} from "./security-result.js";

const SNAPSHOT_SCHEMA_VERSION = 2;
const MAX_DOCUMENTS = 96;
const MAX_URL_RECEIPTS = 96;
const MAX_TABS = 64;
const MAX_PENDING_REQUESTS = 32;
const MAX_NATIVE_CONNECT_DECISIONS = 32;
const MAX_URL_LENGTH = 4096;
const MAX_IDENTIFIER_LENGTH = 160;
const MAX_COMPLETION_CLOCK_SKEW_MS = 60 * 1000;
const MAX_BROWSER_CLOCK_SKEW_MS = 5 * 60 * 1000;
const EARLIEST_BROWSER_TIMESTAMP_MS = 1_577_836_800_000;

const RECEIPT_SOURCES = new Set([
  "rustHttpResponse",
  "rustHttpResponseCache",
  "browserWebPkiPassthrough",
  "browserWebPkiConnectionReuse",
  "browserWebPkiCacheReceipt"
]);
const CACHE_RECEIPT_SOURCES = new Set([
  "rustHttpResponseCache",
  "browserWebPkiCacheReceipt"
]);
const RUST_RECEIPT_SOURCES = new Set([
  "rustHttpResponse",
  "rustHttpResponseCache"
]);
const CONNECT_RECEIPT_SOURCES = new Set([
  "browserWebPkiPassthrough",
  "browserWebPkiConnectionReuse",
  "browserWebPkiCacheReceipt"
]);

export class NavigationReceiptStore {
  constructor(snapshot = null) {
    this.runtime = null;
    this.maintenanceEpoch = 0;
    this.maintenancePending = false;
    this.sequence = 0;
    this.lastNativeEventSequence = 0;
    this.tabs = Object.create(null);
    this.documents = Object.create(null);
    this.urlReceipts = Object.create(null);
    this.pending = Object.create(null);
    this.restore(snapshot);
  }

  ensureRuntime(candidate) {
    const runtime = runtimeTuple(candidate);
    const maintenanceEpoch = validMaintenanceEpoch(
      candidate?.securityMaintenanceEpoch
    );
    if (!runtime || maintenanceEpoch == null) return false;
    if (!sameRuntime(this.runtime, runtime)) {
      this.runtime = runtime;
      this.maintenanceEpoch = maintenanceEpoch;
      this.maintenancePending = false;
      this.sequence = 0;
      this.lastNativeEventSequence = 0;
      this.tabs = Object.create(null);
      this.documents = Object.create(null);
      this.urlReceipts = Object.create(null);
      this.pending = Object.create(null);
    } else if (maintenanceEpoch < this.maintenanceEpoch) {
      return false;
    } else if (maintenanceEpoch > this.maintenanceEpoch) {
      this.maintenanceEpoch = maintenanceEpoch;
      // Epoch observation can race the explicit post-sync completion. Preserve
      // an active maintenance barrier until completeMaintenance validates the
      // authoritative ready status; a normal (non-maintenance) epoch advance
      // keeps the existing false value.
      this.pending = Object.create(null);
    }
    this.noteNativeEvent(candidate);
    return true;
  }

  beginRequest(details, runtimeStatus) {
    if (!this.ensureRuntime(runtimeStatus)) return false;
    if (this.maintenancePending) return false;
    const requestId = boundedIdentifier(details?.requestId);
    const tabId = validTabId(details?.tabId);
    const target = canonicalNavigationUrl(details?.url);
    if (!requestId || tabId == null || !target || details?.type !== "main_frame") {
      return false;
    }

    const existing = this.pending[requestId];
    if (existing) {
      existing.url = target.url;
      existing.origin = target.origin;
      existing.host = target.host;
      existing.port = target.port;
      existing.scheme = target.scheme;
      existing.method = normalizedMethod(details?.method);
      existing.documentId =
        existing.documentId ?? boundedIdentifier(details?.documentId);
      this.markHostConflicts(requestId, target.host);
      return true;
    }

    const pending = {
      requestId,
      tabId,
      documentId: boundedIdentifier(details?.documentId),
      url: target.url,
      origin: target.origin,
      host: target.host,
      port: target.port,
      scheme: target.scheme,
      method: normalizedMethod(details?.method),
      startedAtUnixMs: validBrowserTimestamp(details?.timeStamp),
      eventFloor: this.lastNativeEventSequence,
      maintenanceEpoch: this.maintenanceEpoch,
      ambiguous: false,
      completion: null,
      sequence: this.nextSequence()
    };
    this.pending[requestId] = pending;
    this.markHostConflicts(requestId, target.host);
    this.prunePending();
    return true;
  }

  redirectRequest(details) {
    const requestId = boundedIdentifier(details?.requestId);
    const target = canonicalNavigationUrl(details?.redirectUrl);
    const pending = requestId ? this.pending[requestId] : null;
    if (!pending || !target) return false;
    pending.url = target.url;
    pending.origin = target.origin;
    pending.host = target.host;
    pending.port = target.port;
    pending.scheme = target.scheme;
    pending.documentId =
      pending.documentId ?? boundedIdentifier(details?.documentId);
    this.markHostConflicts(requestId, target.host);
    return true;
  }

  commitDocument(details, unavailableReason = "mainFrameSecurityPending") {
    const tabId = validTabId(details?.tabId);
    const documentId = boundedIdentifier(details?.documentId);
    const target = canonicalNavigationUrl(details?.url);
    if (tabId == null) return false;
    if (
      typeof details?.documentLifecycle === "string" &&
      details.documentLifecycle !== "active"
    ) {
      return false;
    }
    if (!documentId || !target || details?.frameId !== 0) {
      this.tabs[String(tabId)] = {
        documentId: null,
        url: target?.url ?? null,
        unavailableReason: "unsupportedMainFrame",
        sequence: this.nextSequence()
      };
      this.prune();
      return false;
    }

    const existing = this.documents[documentId];
    if (existing) {
      if (existing.origin !== target.origin) {
        existing.receipt = null;
        existing.connectDecisionReceipt = null;
        existing.receiptEpoch = null;
        existing.source = null;
        existing.unavailableReason = "historyOriginMismatch";
      }
      existing.tabId = tabId;
      existing.url = target.url;
      existing.origin = target.origin;
      existing.host = target.host;
      existing.port = target.port;
      existing.scheme = target.scheme;
      existing.restored =
        existing.restored ||
        Array.isArray(details?.transitionQualifiers) &&
          details.transitionQualifiers.includes("forward_back");
      existing.sequence = this.nextSequence();
      this.tabs[String(tabId)] = {
        documentId,
        url: target.url,
        unavailableReason: null,
        sequence: existing.sequence
      };
      this.prune();
      return true;
    }

    const pending = this.pendingForDocument(tabId, documentId, target.url);
    const document = {
      documentId,
      tabId,
      url: target.url,
      origin: target.origin,
      host: target.host,
      port: target.port,
      scheme: target.scheme,
      receipt: null,
      connectDecisionReceipt: null,
      receiptEpoch: null,
      source: null,
      restored:
        Array.isArray(details?.transitionQualifiers) &&
        details.transitionQualifiers.includes("forward_back"),
      unavailableReason: pending ? "mainFrameSecurityPending" : unavailableReason,
      sequence: this.nextSequence()
    };
    this.documents[documentId] = document;
    this.tabs[String(tabId)] = {
      documentId,
      url: target.url,
      unavailableReason: null,
      sequence: document.sequence
    };
    if (pending) {
      pending.documentId = documentId;
      if (pending.completion) {
        this.bindCompletion(document, pending.completion);
        delete this.pending[pending.requestId];
      }
    }
    this.prune();
    return true;
  }

  updateDocumentUrl(details) {
    return this.commitDocument(details, "historyDocumentReceiptUnavailable");
  }

  completeRequest(details, runtimeStatus) {
    const requestId = boundedIdentifier(details?.requestId);
    const pending = requestId ? this.pending[requestId] : null;
    if (!pending) return false;

    const target = canonicalNavigationUrl(details?.url);
    if (!target || validTabId(details?.tabId) !== pending.tabId) {
      delete this.pending[requestId];
      return false;
    }
    pending.url = target.url;
    pending.origin = target.origin;
    pending.host = target.host;
    pending.port = target.port;
    pending.scheme = target.scheme;
    pending.documentId =
      pending.documentId ?? boundedIdentifier(details?.documentId);

    const completion =
      details?.fromCache === true
        ? this.cachedCompletion(pending, details, runtimeStatus)
        : this.networkCompletion(pending, details, runtimeStatus);
    const documentId =
      pending.documentId ??
      this.documentIdForTabAndUrl(pending.tabId, target.url);
    const document = documentId ? this.documents[documentId] : null;
    if (document) {
      this.bindCompletion(document, completion);
      delete this.pending[requestId];
    } else {
      pending.completion = completion;
    }
    this.prune();
    return completion.receipt != null || completion.connectDecisionReceipt != null;
  }

  failRequest(details) {
    const requestId = boundedIdentifier(details?.requestId);
    if (!requestId || !this.pending[requestId]) return false;
    delete this.pending[requestId];
    return true;
  }

  failNavigation(details) {
    const tabId = validTabId(details?.tabId);
    if (tabId == null || details?.frameId !== 0) return false;
    for (const [requestId, pending] of Object.entries(this.pending)) {
      if (pending.tabId === tabId) delete this.pending[requestId];
    }
    this.tabs[String(tabId)] = {
      documentId: null,
      url: canonicalNavigationUrl(details?.url)?.url ?? null,
      unavailableReason: "mainFrameNavigationFailed",
      sequence: this.nextSequence()
    };
    this.prune();
    return true;
  }

  beginMaintenance(runtimeStatus) {
    if (!this.ensureRuntime(runtimeStatus)) return false;
    this.maintenancePending = true;
    this.pending = Object.create(null);
    return true;
  }

  completeMaintenance(
    runtimeStatus,
    nowUnixSeconds = Math.floor(Date.now() / 1000)
  ) {
    const wasPending = this.maintenancePending;
    if (
      !wasPending ||
      !maintenanceCompletionReady(runtimeStatus, nowUnixSeconds) ||
      !this.ensureRuntime(runtimeStatus)
    ) {
      return false;
    }
    this.maintenancePending = false;
    this.pending = Object.create(null);
    return true;
  }

  removeTab(tabId) {
    const valid = validTabId(tabId);
    if (valid == null) return false;
    delete this.tabs[String(valid)];
    for (const [documentId, document] of Object.entries(this.documents)) {
      if (document.tabId === valid) delete this.documents[documentId];
    }
    for (const [requestId, pending] of Object.entries(this.pending)) {
      if (pending.tabId === valid) delete this.pending[requestId];
    }
    return true;
  }

  replaceTab(addedTabId, removedTabId) {
    const added = validTabId(addedTabId);
    const removed = validTabId(removedTabId);
    if (added == null || removed == null) return false;
    const tab = this.tabs[String(removed)];
    if (tab) {
      delete this.tabs[String(removed)];
      tab.sequence = this.nextSequence();
      this.tabs[String(added)] = tab;
      if (tab.documentId && this.documents[tab.documentId]) {
        this.documents[tab.documentId].tabId = added;
      }
    }
    for (const pending of Object.values(this.pending)) {
      if (pending.tabId === removed) pending.tabId = added;
    }
    return true;
  }

  receiptForTab(tabId, runtimeStatus) {
    if (!this.ensureRuntime(runtimeStatus)) {
      return unavailableReceipt("runtimeGenerationUnavailable");
    }
    const valid = validTabId(tabId);
    if (valid == null) return unavailableReceipt("noActiveBrowserTab");
    const tab = this.tabs[String(valid)];
    if (!tab?.documentId) {
      return unavailableReceipt(
        tab?.unavailableReason ?? "activeDocumentReceiptUnavailable"
      );
    }
    const document = this.documents[tab.documentId];
    if (!document) return unavailableReceipt("activeDocumentReceiptUnavailable");
    const receipt = currentSecurityResult(document.receipt, this.runtime);
    const connectDecisionReceipt = currentConnectReceipt(
      document.connectDecisionReceipt,
      this.runtimeAtEpoch(document.receiptEpoch),
      document
    );
    if (
      (!receipt || receipt.mainFrame !== true) &&
      !connectDecisionReceipt
    ) {
      return unavailableReceipt(
        document.unavailableReason ?? "mainFrameSecurityReceiptUnavailable"
      );
    }
    let state = "currentDocument";
    if (
      this.maintenancePending ||
      document.receiptEpoch < this.maintenanceEpoch
    ) {
      state = "committedBeforeHeaderMaintenance";
    } else if (CACHE_RECEIPT_SOURCES.has(document.source)) {
      state = "browserCacheReceipt";
    } else if (document.restored) {
      state = "restoredDocument";
    }
    return {
      receipt,
      connectDecisionReceipt,
      unavailableReason: null,
      state,
      source: document.source
    };
  }

  providerAuthorityForDocument(tabId, documentId, origin, runtimeStatus, documentUrl = null) {
    if (
      !this.ensureRuntime(runtimeStatus) ||
      runtimeStatus?.state !== "active" ||
      runtimeStatus?.proxyActive !== true ||
      this.maintenancePending
    ) {
      return null;
    }
    const validTab = validTabId(tabId);
    const validDocument = boundedIdentifier(documentId);
    if (validTab == null || !validDocument || typeof origin !== "string") {
      return null;
    }
    const tab = this.tabs[String(validTab)];
    const document = this.documents[validDocument];
    const requestedUrl =
      documentUrl == null ? null : canonicalNavigationUrl(documentUrl);
    if (
      tab?.documentId !== validDocument ||
      !document ||
      document.tabId !== validTab ||
      document.origin !== origin ||
      (documentUrl != null && (!requestedUrl || document.url !== requestedUrl.url)) ||
      document.scheme !== "https:" ||
      document.restored ||
      document.receiptEpoch !== this.maintenanceEpoch
    ) {
      return null;
    }
    const receipt = currentSecurityResult(document.receipt, this.runtime);
    const connectDecisionReceipt = currentConnectReceipt(
      document.connectDecisionReceipt,
      this.runtimeAtEpoch(document.receiptEpoch),
      document
    );
    const decision = receipt ?? connectDecisionReceipt;
    if (
      !decision ||
      decision.canonicalStatus !== "available" ||
      !["hns", "icann"].includes(decision.selectedNamespace) ||
      decision.host !== document.host ||
      decision.runtimeSession !== this.runtime.runtimeSession ||
      decision.runtimeGeneration !== this.runtime.runtimeGeneration ||
      decision.policyGeneration !== this.runtime.policyGeneration
    ) {
      return null;
    }
    return Object.freeze({
      origin: document.origin,
      namespace: decision.selectedNamespace,
      network: decision.network,
      browserAuthoritySession: decision.runtimeSession,
      runtimeGeneration: decision.runtimeGeneration,
      policyGeneration: decision.policyGeneration,
      navigationGeneration: document.sequence,
      documentId: document.documentId,
      decisionFingerprint: decision.decisionFingerprint ?? null
    });
  }

  snapshot() {
    return {
      schemaVersion: SNAPSHOT_SCHEMA_VERSION,
      runtime: this.runtime,
      maintenanceEpoch: this.maintenanceEpoch,
      maintenancePending: this.maintenancePending,
      sequence: this.sequence,
      lastNativeEventSequence: this.lastNativeEventSequence,
      tabs: this.tabs,
      documents: this.documents,
      urlReceipts: this.urlReceipts
    };
  }

  restore(snapshot) {
    if (
      !isRecord(snapshot) ||
      snapshot.schemaVersion !== SNAPSHOT_SCHEMA_VERSION ||
      !runtimeTuple(snapshot.runtime) ||
      !Number.isSafeInteger(snapshot.maintenanceEpoch) ||
      snapshot.maintenanceEpoch < 1 ||
      typeof snapshot.maintenancePending !== "boolean"
    ) {
      return;
    }
    this.runtime = runtimeTuple(snapshot.runtime);
    this.maintenanceEpoch = snapshot.maintenanceEpoch;
    this.maintenancePending = snapshot.maintenancePending;
    this.sequence =
      Number.isSafeInteger(snapshot.sequence) && snapshot.sequence >= 0
        ? snapshot.sequence
        : 0;
    this.lastNativeEventSequence =
      Number.isSafeInteger(snapshot.lastNativeEventSequence) &&
      snapshot.lastNativeEventSequence >= 0
        ? snapshot.lastNativeEventSequence
        : 0;

    for (const [documentId, candidate] of boundedEntries(
      snapshot.documents,
      MAX_DOCUMENTS
    )) {
      const document = restoredDocument(documentId, candidate, this.runtime);
      if (!document || document.receiptEpoch > this.maintenanceEpoch) continue;
      this.documents[documentId] = document;
      this.lastNativeEventSequence = Math.max(
        this.lastNativeEventSequence,
        receiptEventSequence(document)
      );
    }
    for (const [url, candidate] of boundedEntries(
      snapshot.urlReceipts,
      MAX_URL_RECEIPTS
    )) {
      const restored = restoredUrlReceipt(url, candidate, this.runtime);
      if (!restored || restored.receiptEpoch > this.maintenanceEpoch) continue;
      this.urlReceipts[url] = restored;
      this.lastNativeEventSequence = Math.max(
        this.lastNativeEventSequence,
        receiptEventSequence(restored)
      );
    }
    for (const [tabId, candidate] of boundedEntries(snapshot.tabs, MAX_TABS)) {
      if (
        !/^(0|[1-9][0-9]*)$/.test(tabId) ||
        validTabId(Number(tabId)) == null ||
        !isRecord(candidate)
      ) {
        continue;
      }
      const documentId = boundedIdentifier(candidate.documentId);
      if (!documentId || !this.documents[documentId]) continue;
      this.tabs[tabId] = {
        documentId,
        url: this.documents[documentId].url,
        unavailableReason: null,
        sequence: validSequence(candidate.sequence)
      };
    }
    this.prune();
  }

  cachedCompletion(pending, details, runtimeStatus) {
    const completionRuntime = runtimeTuple(runtimeStatus);
    const completionEpoch = validMaintenanceEpoch(
      runtimeStatus?.securityMaintenanceEpoch
    );
    if (
      !completionRuntime ||
      completionEpoch == null ||
      !sameRuntime(this.runtime, completionRuntime)
    ) {
      this.ensureRuntime(runtimeStatus);
      return unavailableCompletion("runtimeGenerationChanged");
    }
    if (!this.ensureRuntime(runtimeStatus)) {
      return unavailableCompletion("runtimeGenerationUnavailable");
    }
    const cached = this.urlReceipts[pending.url];
    if (
      this.maintenancePending ||
      pending.maintenanceEpoch !== this.maintenanceEpoch ||
      cached?.receiptEpoch !== this.maintenanceEpoch ||
      !["GET", "HEAD"].includes(pending.method)
    ) {
      return unavailableCompletion("browserCacheReceiptUnavailable");
    }
    const receipt =
      currentSecurityResult(cached.receipt, this.runtime);
    if (
      receipt?.mainFrame === true &&
      receipt.host === pending.host &&
      Number.isInteger(receipt.statusCode) &&
      receipt.statusCode === details?.statusCode
    ) {
      return {
        receipt,
        connectDecisionReceipt: null,
        receiptEpoch: this.maintenanceEpoch,
        source: "rustHttpResponseCache",
        unavailableReason: null
      };
    }
    const connectDecisionReceipt = currentConnectReceipt(
      cached.connectDecisionReceipt,
      this.runtimeAtEpoch(this.maintenanceEpoch),
      pending
    );
    if (
      connectDecisionReceipt &&
      connectDecisionReceipt.browserStatusCode === details?.statusCode
    ) {
      return {
        receipt: null,
        connectDecisionReceipt,
        receiptEpoch: this.maintenanceEpoch,
        source: "browserWebPkiCacheReceipt",
        unavailableReason: null
      };
    }
    return unavailableCompletion("browserCacheReceiptUnavailable");
  }

  networkCompletion(pending, details, runtimeStatus) {
    const completionRuntime = runtimeTuple(runtimeStatus);
    const completionEpoch = validMaintenanceEpoch(
      runtimeStatus?.securityMaintenanceEpoch
    );
    if (!completionRuntime || completionEpoch == null) {
      return unavailableCompletion("runtimeGenerationUnavailable");
    }
    if (!sameRuntime(this.runtime, completionRuntime)) {
      this.ensureRuntime(runtimeStatus);
      return unavailableCompletion("runtimeGenerationChanged");
    }
    if (!this.ensureRuntime(runtimeStatus) || this.maintenancePending) {
      return unavailableCompletion("headerMaintenanceInvalidatedNavigation");
    }
    const candidate = currentSecurityResult(
      runtimeStatus?.latestMainFrameSecurity,
      this.runtime
    );
    if (candidate) {
      this.lastNativeEventSequence = Math.max(
        this.lastNativeEventSequence,
        candidate.eventSequence
      );
    }
    if (pending.maintenanceEpoch !== this.maintenanceEpoch) {
      return unavailableCompletion("headerMaintenanceInvalidatedNavigation");
    }
    if (pending.ambiguous) {
      return unavailableCompletion("ambiguousMainFrameObservation");
    }
    if (!["GET", "HEAD"].includes(pending.method)) {
      return unavailableCompletion("unsupportedMainFrameMethod");
    }
    const matchingResponse =
      candidate?.mainFrame === true &&
      candidate.host === pending.host &&
      candidate.eventSequence > pending.eventFloor &&
      Number.isInteger(candidate.statusCode) &&
      candidate.statusCode === details?.statusCode;
    if (matchingResponse) {
      const completion = {
        receipt: candidate,
        connectDecisionReceipt: null,
        receiptEpoch: this.maintenanceEpoch,
        source: "rustHttpResponse",
        unavailableReason: null
      };
      this.urlReceipts[pending.url] = {
        ...completion,
        sequence: this.nextSequence()
      };
      return completion;
    }
    const connectCompletion = this.connectDecisionCompletion(
      pending,
      details,
      runtimeStatus
    );
    if (!connectCompletion.connectDecisionReceipt) {
      return candidate
        ? unavailableCompletion("mainFrameSecurityReceiptMismatch")
        : connectCompletion;
    }
    this.urlReceipts[pending.url] = {
      ...connectCompletion,
      sequence: this.nextSequence()
    };
    return connectCompletion;
  }

  connectDecisionCompletion(pending, details, runtimeStatus) {
    const completedAtUnixMs = validBrowserTimestamp(details?.timeStamp);
    const decisions = runtimeStatus?.recentConnectSecurityDecisions;
    if (
      pending.scheme !== "https:" ||
      pending.startedAtUnixMs == null ||
      completedAtUnixMs == null ||
      completedAtUnixMs + MAX_COMPLETION_CLOCK_SKEW_MS <
        pending.startedAtUnixMs ||
      !validHttpStatus(details?.statusCode) ||
      !Array.isArray(decisions) ||
      decisions.length > MAX_NATIVE_CONNECT_DECISIONS
    ) {
      return unavailableCompletion("connectSecurityDecisionUnavailable");
    }
    const matches = decisions
      .map((decision) =>
        currentConnectSecurityDecision(
          decision,
          runtimeStatus,
          Math.max(Date.now(), completedAtUnixMs)
        )
      )
      .filter(
        (decision) =>
          decision &&
          decision.host === pending.host &&
          decision.port === pending.port &&
          decision.observedAtUnixMs <=
            completedAtUnixMs + MAX_COMPLETION_CLOCK_SKEW_MS
      );
    const fresh = matches.filter(
      (decision) =>
        decision.eventSequence > pending.eventFloor &&
        decision.observedAtUnixMs >= pending.startedAtUnixMs
    );
    const freshSelection = newestEquivalentConnectDecision(fresh);
    if (freshSelection.ambiguous) {
      return unavailableCompletion("ambiguousConnectSecurityDecision");
    }
    if (freshSelection.decision) {
      return connectCompletion(
        freshSelection.decision,
        details.statusCode,
        completedAtUnixMs,
        this.maintenanceEpoch,
        "browserWebPkiPassthrough"
      );
    }
    const retained = matches.filter(
      (decision) => decision.observedAtUnixMs < pending.startedAtUnixMs
    );
    const retainedSelection = newestEquivalentConnectDecision(retained);
    if (retainedSelection.ambiguous || !retainedSelection.decision) {
      return unavailableCompletion(
        retainedSelection.ambiguous
          ? "ambiguousConnectSecurityDecision"
          : "connectSecurityDecisionUnavailable"
      );
    }
    return connectCompletion(
      retainedSelection.decision,
      details.statusCode,
      completedAtUnixMs,
      this.maintenanceEpoch,
      "browserWebPkiConnectionReuse"
    );
  }

  bindCompletion(document, completion) {
    const source = RECEIPT_SOURCES.has(completion.source)
      ? completion.source
      : null;
    if (
      RUST_RECEIPT_SOURCES.has(source) &&
      completion.receipt &&
      currentSecurityResult(completion.receipt, this.runtime) &&
      completion.receipt.host === document.host
    ) {
      document.receipt = completion.receipt;
      document.connectDecisionReceipt = null;
      document.receiptEpoch = completion.receiptEpoch;
      document.source = source;
      document.unavailableReason = null;
    } else if (
      CONNECT_RECEIPT_SOURCES.has(source) &&
      currentConnectReceipt(
        completion.connectDecisionReceipt,
        this.runtimeAtEpoch(completion.receiptEpoch),
        document
      )
    ) {
      document.receipt = null;
      document.connectDecisionReceipt = completion.connectDecisionReceipt;
      document.receiptEpoch = completion.receiptEpoch;
      document.source = source;
      document.unavailableReason = null;
    } else {
      document.receipt = null;
      document.connectDecisionReceipt = null;
      document.receiptEpoch = null;
      document.source = null;
      document.unavailableReason =
        completion.unavailableReason ?? "mainFrameSecurityReceiptUnavailable";
    }
    document.sequence = this.nextSequence();
  }

  runtimeAtEpoch(maintenanceEpoch) {
    return validMaintenanceEpoch(maintenanceEpoch) == null
      ? null
      : {
          ...this.runtime,
          securityMaintenanceEpoch: maintenanceEpoch
        };
  }

  pendingForDocument(tabId, documentId, url) {
    const candidates = Object.values(this.pending)
      .filter(
        (pending) =>
          pending.tabId === tabId &&
          (pending.documentId === documentId || pending.url === url)
      )
      .sort((left, right) => right.sequence - left.sequence);
    return candidates[0] ?? null;
  }

  documentIdForTabAndUrl(tabId, url) {
    const tab = this.tabs[String(tabId)];
    if (!tab?.documentId || tab.url !== url) return null;
    return tab.documentId;
  }

  markHostConflicts(requestId, host) {
    const current = this.pending[requestId];
    if (!current) return;
    for (const pending of Object.values(this.pending)) {
      if (
        pending.requestId !== requestId &&
        pending.maintenanceEpoch === current.maintenanceEpoch &&
        pending.host === host
      ) {
        pending.ambiguous = true;
        current.ambiguous = true;
      }
    }
  }

  noteNativeEvent(runtimeStatus) {
    const candidate = currentSecurityResult(
      runtimeStatus?.latestMainFrameSecurity,
      this.runtime
    );
    if (candidate) {
      this.lastNativeEventSequence = Math.max(
        this.lastNativeEventSequence,
        candidate.eventSequence
      );
    }
    const decisions = runtimeStatus?.recentConnectSecurityDecisions;
    if (!Array.isArray(decisions) || decisions.length > MAX_NATIVE_CONNECT_DECISIONS) {
      return;
    }
    const authority = this.runtimeAtEpoch(this.maintenanceEpoch);
    for (const decision of decisions) {
      const current = currentConnectSecurityDecision(decision, authority);
      if (current) {
        this.lastNativeEventSequence = Math.max(
          this.lastNativeEventSequence,
          current.eventSequence
        );
      }
    }
  }

  nextSequence() {
    this.sequence =
      this.sequence < Number.MAX_SAFE_INTEGER ? this.sequence + 1 : 1;
    return this.sequence;
  }

  prunePending() {
    pruneObject(this.pending, MAX_PENDING_REQUESTS, () => false);
  }

  prune() {
    const activeDocuments = new Set(
      Object.values(this.tabs)
        .map((tab) => tab.documentId)
        .filter(Boolean)
    );
    pruneObject(
      this.documents,
      MAX_DOCUMENTS,
      (documentId) => activeDocuments.has(documentId)
    );
    pruneObject(this.urlReceipts, MAX_URL_RECEIPTS, () => false);
    pruneObject(this.tabs, MAX_TABS, () => false);
    this.prunePending();
  }
}

function maintenanceCompletionReady(candidate, nowUnixSeconds) {
  const validUntil = candidate?.headerSync?.targetEvidenceValidUntilUnix;
  return Boolean(
    Number.isSafeInteger(nowUnixSeconds) &&
      nowUnixSeconds >= 0 &&
      candidate?.state === "active" &&
      candidate?.proxyActive === true &&
      candidate?.headerSync?.treeRootReady === true &&
      candidate?.headerSync?.blocksUntilAuthoritativeTreeRoot === 0 &&
      candidate?.headerSync?.targetEvidenceExpired === false &&
      Number.isSafeInteger(validUntil) &&
      validUntil > nowUnixSeconds
  );
}

export function registerNavigationLifecycle(chromeApi, handlers) {
  const requestFilter = { urls: ["<all_urls>"], types: ["main_frame"] };
  chromeApi.webRequest.onBeforeRequest.addListener(
    (details) => handlers.beforeRequest(details),
    requestFilter
  );
  chromeApi.webRequest.onBeforeRedirect.addListener(
    (details) => handlers.beforeRedirect(details),
    requestFilter
  );
  chromeApi.webRequest.onCompleted.addListener(
    (details) => handlers.completed(details),
    requestFilter
  );
  chromeApi.webRequest.onErrorOccurred.addListener(
    (details) => handlers.requestError(details),
    requestFilter
  );
  chromeApi.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0) handlers.committed(details);
  });
  chromeApi.webNavigation.onHistoryStateUpdated.addListener((details) => {
    if (details.frameId === 0) handlers.historyUpdated(details);
  });
  chromeApi.webNavigation.onReferenceFragmentUpdated.addListener((details) => {
    if (details.frameId === 0) handlers.historyUpdated(details);
  });
  chromeApi.webNavigation.onErrorOccurred.addListener((details) => {
    if (details.frameId === 0) handlers.navigationError(details);
  });
  chromeApi.tabs.onRemoved.addListener((tabId) => handlers.tabRemoved(tabId));
  chromeApi.tabs.onReplaced.addListener((addedTabId, removedTabId) =>
    handlers.tabReplaced(addedTabId, removedTabId)
  );
}

export function canonicalNavigationUrl(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_URL_LENGTH) {
    return null;
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (!["http:", "https:"].includes(parsed.protocol)) return null;
  if (parsed.username || parsed.password) return null;
  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253 || isIpLiteral(host)) return null;
  const port = Number(parsed.port || (parsed.protocol === "https:" ? "443" : "80"));
  if (!Number.isInteger(port) || port < 1 || port > 65_535) return null;
  parsed.hash = "";
  return {
    url: parsed.href,
    origin: parsed.origin,
    host,
    port,
    scheme: parsed.protocol
  };
}

function runtimeTuple(candidate) {
  if (
    !isRecord(candidate) ||
    typeof candidate.runtimeSession !== "string" ||
    candidate.runtimeSession.length < 1 ||
    candidate.runtimeSession.length > MAX_IDENTIFIER_LENGTH ||
    !Number.isSafeInteger(candidate.runtimeGeneration) ||
    candidate.runtimeGeneration < 1 ||
    !Number.isSafeInteger(candidate.policyGeneration) ||
    candidate.policyGeneration < 1
  ) {
    return null;
  }
  return {
    runtimeSession: candidate.runtimeSession,
    runtimeGeneration: candidate.runtimeGeneration,
    policyGeneration: candidate.policyGeneration
  };
}

function sameRuntime(left, right) {
  return (
    left?.runtimeSession === right?.runtimeSession &&
    left?.runtimeGeneration === right?.runtimeGeneration &&
    left?.policyGeneration === right?.policyGeneration
  );
}

function restoredDocument(documentId, candidate, runtime) {
  if (!boundedIdentifier(documentId) || !isRecord(candidate)) return null;
  const target = canonicalNavigationUrl(candidate.url);
  const tabId = validTabId(candidate.tabId);
  const receiptEpoch = validMaintenanceEpoch(candidate.receiptEpoch);
  const receipt = currentSecurityResult(candidate.receipt, runtime);
  const connectDecisionReceipt = currentConnectReceipt(
    candidate.connectDecisionReceipt,
    runtimeAtEpoch(runtime, receiptEpoch),
    target
  );
  if (
    !target ||
    tabId == null ||
    receiptEpoch == null ||
    ((!receipt ||
      receipt.mainFrame !== true ||
      receipt.host !== target.host) &&
      !connectDecisionReceipt) ||
    (receipt && connectDecisionReceipt) ||
    !sourceMatchesReceipt(candidate.source, receipt, connectDecisionReceipt)
  ) {
    return null;
  }
  return {
    documentId,
    tabId,
    url: target.url,
    origin: target.origin,
    host: target.host,
    port: target.port,
    scheme: target.scheme,
    receipt,
    connectDecisionReceipt,
    receiptEpoch,
    source: candidate.source,
    restored: candidate.restored === true,
    unavailableReason: null,
    sequence: validSequence(candidate.sequence)
  };
}

function restoredUrlReceipt(url, candidate, runtime) {
  if (!isRecord(candidate)) return null;
  const target = canonicalNavigationUrl(url);
  const receiptEpoch = validMaintenanceEpoch(candidate.receiptEpoch);
  const receipt = currentSecurityResult(candidate.receipt, runtime);
  const connectDecisionReceipt = currentConnectReceipt(
    candidate.connectDecisionReceipt,
    runtimeAtEpoch(runtime, receiptEpoch),
    target
  );
  if (
    !target ||
    target.url !== url ||
    receiptEpoch == null ||
    ((!receipt ||
      receipt.mainFrame !== true ||
      receipt.host !== target.host) &&
      !connectDecisionReceipt) ||
    (receipt && connectDecisionReceipt) ||
    !sourceMatchesReceipt(candidate.source, receipt, connectDecisionReceipt)
  ) {
    return null;
  }
  return {
    receipt,
    connectDecisionReceipt,
    receiptEpoch,
    source: candidate.source,
    sequence: validSequence(candidate.sequence)
  };
}

function connectCompletion(
  nativeDecision,
  browserStatusCode,
  browserCompletedAtUnixMs,
  receiptEpoch,
  source
) {
  return {
    receipt: null,
    connectDecisionReceipt: {
      schemaVersion: 1,
      receiptKind: "browserWebPkiDocumentReceipt",
      nativeDecision,
      browserStatusCode,
      browserCompletedAtUnixMs
    },
    receiptEpoch,
    source,
    unavailableReason: null
  };
}

function currentConnectReceipt(candidate, runtime, expectedTarget) {
  if (
    !isRecord(candidate) ||
    candidate.schemaVersion !== 1 ||
    candidate.receiptKind !== "browserWebPkiDocumentReceipt" ||
    Object.hasOwn(candidate, "statusCode") ||
    Object.hasOwn(candidate, "mainFrame") ||
    !validHttpStatus(candidate.browserStatusCode) ||
    validBrowserTimestamp(candidate.browserCompletedAtUnixMs) == null ||
    !isRecord(expectedTarget) ||
    expectedTarget.scheme !== "https:"
  ) {
    return null;
  }
  const nativeDecision = currentConnectSecurityDecision(
    candidate.nativeDecision,
    runtime,
    Math.max(Date.now(), candidate.browserCompletedAtUnixMs)
  );
  if (
    !nativeDecision ||
    nativeDecision.host !== expectedTarget.host ||
    nativeDecision.port !== expectedTarget.port ||
    nativeDecision.observedAtUnixMs >
      candidate.browserCompletedAtUnixMs + MAX_COMPLETION_CLOCK_SKEW_MS
  ) {
    return null;
  }
  return candidate;
}

function runtimeAtEpoch(runtime, maintenanceEpoch) {
  return runtime && validMaintenanceEpoch(maintenanceEpoch) != null
    ? {
        ...runtime,
        securityMaintenanceEpoch: maintenanceEpoch
      }
    : null;
}

function sourceMatchesReceipt(source, receipt, connectDecisionReceipt) {
  return (
    (receipt != null &&
      connectDecisionReceipt == null &&
      RUST_RECEIPT_SOURCES.has(source)) ||
    (receipt == null &&
      connectDecisionReceipt != null &&
      CONNECT_RECEIPT_SOURCES.has(source))
  );
}

function receiptEventSequence(container) {
  return (
    container?.receipt?.eventSequence ??
    container?.connectDecisionReceipt?.nativeDecision?.eventSequence ??
    0
  );
}

function newestEquivalentConnectDecision(candidates) {
  if (candidates.length === 0) {
    return { decision: null, ambiguous: false };
  }
  const evidence = connectSecurityEvidence(candidates[0]);
  if (
    evidence == null ||
    candidates.some(
      (candidate) => connectSecurityEvidence(candidate) !== evidence
    )
  ) {
    return { decision: null, ambiguous: true };
  }
  const decision = candidates.reduce((newest, candidate) => {
    if (candidate.eventSequence !== newest.eventSequence) {
      return candidate.eventSequence > newest.eventSequence
        ? candidate
        : newest;
    }
    return candidate.observedAtUnixMs > newest.observedAtUnixMs
      ? candidate
      : newest;
  });
  return { decision, ambiguous: false };
}

function connectSecurityEvidence(decision) {
  if (
    typeof decision?.decisionFingerprint !== "string" ||
    decision.decisionFingerprint.length === 0
  ) {
    return null;
  }
  return JSON.stringify([
    decision.decisionFingerprint,
    decision.network,
    decision.canonicalStatus,
    decision.namespaceOutcome,
    decision.selectedNamespace,
    decision.namespaceSelectionReason,
    decision.hnsRootFailure,
    decision.icannRootFailure,
    decision.hnsResolutionState,
    decision.icannResolutionState,
    decision.icannTlsAction,
    decision.icannDnssecStatus,
    decision.actualSelectedTransport,
    decision.nameserverAuthority,
    decision.localHnsProofState,
    decision.localDnssecState,
    decision.localTlsaState,
    decision.localDaneState,
    decision.peerIdentity,
    decision.proxyIdentity,
    decision.targetIdentity,
    decision.proxyTargetSeparation,
    decision.directRelayFallback,
    decision.registryProfile,
    decision.registryFingerprint,
    decision.protocolVersion
  ]);
}

function unavailableCompletion(unavailableReason) {
  return {
    receipt: null,
    connectDecisionReceipt: null,
    receiptEpoch: null,
    source: null,
    unavailableReason
  };
}

function unavailableReceipt(unavailableReason) {
  return {
    receipt: null,
    connectDecisionReceipt: null,
    unavailableReason,
    state: "unavailable",
    source: null
  };
}

function normalizedMethod(value) {
  return typeof value === "string" ? value.toUpperCase() : "";
}

function validTabId(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function boundedIdentifier(value) {
  return typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_IDENTIFIER_LENGTH
    ? value
    : null;
}

function validSequence(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function validMaintenanceEpoch(value) {
  return Number.isSafeInteger(value) && value >= 1 ? value : null;
}

function validHttpStatus(value) {
  return Number.isInteger(value) && value >= 100 && value <= 599;
}

function validBrowserTimestamp(value, nowUnixMs = Date.now()) {
  return Number.isFinite(value) &&
    value >= EARLIEST_BROWSER_TIMESTAMP_MS &&
    value <= nowUnixMs + MAX_BROWSER_CLOCK_SKEW_MS
    ? value
    : null;
}

function boundedEntries(value, limit) {
  return isRecord(value) ? Object.entries(value).slice(0, limit) : [];
}

function pruneObject(value, limit, protectedKey) {
  const entries = Object.entries(value);
  if (entries.length <= limit) return;
  entries
    .sort(([, left], [, right]) => validSequence(left.sequence) - validSequence(right.sequence))
    .filter(([key]) => !protectedKey(key))
    .slice(0, entries.length - limit)
    .forEach(([key]) => delete value[key]);
  if (Object.keys(value).length <= limit) return;
  Object.entries(value)
    .sort(([, left], [, right]) => validSequence(left.sequence) - validSequence(right.sequence))
    .slice(0, Object.keys(value).length - limit)
    .forEach(([key]) => delete value[key]);
}

function isIpLiteral(host) {
  if (host.includes(":")) return true;
  const parts = host.split(".");
  return (
    parts.length === 4 &&
    parts.every(
      (part) =>
        /^(0|[1-9][0-9]{0,2})$/.test(part) &&
        Number(part) >= 0 &&
        Number(part) <= 255
    )
  );
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
