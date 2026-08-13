export const LEGAL_DOCUMENTS = Object.freeze([
  Object.freeze({ id: "privacy", path: "PRIVACY.md", outputId: "privacy-document" }),
  Object.freeze({ id: "license", path: "LICENSE", outputId: "license-document" }),
  Object.freeze({
    id: "notices",
    path: "THIRD_PARTY_NOTICES.txt",
    outputId: "notices-document"
  })
]);

if (globalThis.document) void initializeLegalPage();

export async function initializeLegalPage({
  runtime = globalThis.chrome?.runtime,
  documentObject = globalThis.document,
  fetchText = fetchLegalText
} = {}) {
  if (!runtime?.getURL || !documentObject) return;

  const version = runtime.getManifest?.()?.version;
  if (typeof version === "string" && /^\d+(?:\.\d+){2,3}$/.test(version)) {
    documentObject.querySelector("#legal-version").textContent = `version ${version}`;
  }

  await Promise.all(
    LEGAL_DOCUMENTS.map(async (descriptor) => {
      const output = documentObject.querySelector(`#${descriptor.outputId}`);
      try {
        output.textContent = await fetchText(runtime.getURL(descriptor.path));
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        output.textContent = `Bundled document unavailable: ${detail}`;
      }
    })
  );

  openRequestedSection(documentObject, globalThis.location?.hash);
  globalThis.addEventListener?.("hashchange", () => {
    openRequestedSection(documentObject, globalThis.location?.hash);
  });
}

export function legalSectionFromHash(hash) {
  const id = String(hash ?? "").replace(/^#/, "");
  return ["privacy", "license", "agreement", "notices"].includes(id)
    ? id
    : "privacy";
}

export function openRequestedSection(documentObject, hash) {
  const sectionId = legalSectionFromHash(hash);
  const details = documentObject.querySelector(
    `#${sectionId} details[data-legal-document]`
  );
  if (details) details.open = true;
  return sectionId;
}

async function fetchLegalText(url) {
  const response = await fetch(url, { cache: "no-store", credentials: "omit" });
  if (!response.ok) throw new Error(`read failed (${response.status})`);
  return response.text();
}
