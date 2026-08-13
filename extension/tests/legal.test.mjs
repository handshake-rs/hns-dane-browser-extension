import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  LEGAL_DOCUMENTS,
  initializeLegalPage,
  legalSectionFromHash,
  openRequestedSection
} from "../src/legal.js";
import { DEFAULT_POLICY } from "../src/policy.js";

const legalPage = readFileSync("extension/src/legal.html", "utf8");
const legalScript = readFileSync("extension/src/legal.js", "utf8");
const options = readFileSync("extension/src/options.html", "utf8");
const popup = readFileSync("extension/src/popup.html", "utf8");
const popupScript = readFileSync("extension/src/popup.js", "utf8");
const setup = readFileSync("extension/src/setup.html", "utf8");
const buildScript = readFileSync("extension/scripts/build.mjs", "utf8");

test("the internal legal screen exposes the same disclosure groups as mobile", () => {
  for (const section of ["privacy", "license", "agreement", "notices"]) {
    assert.match(legalPage, new RegExp(`id="${section}"`));
    assert.match(legalPage, new RegExp(`href="#${section}"`));
  }
  assert.match(legalPage, /User agreement/);
  assert.match(legalPage, /PolyForm Noncommercial License 1\.0\.0/);
  assert.match(legalPage, /not a\s+financial service/);
  assert.match(legalPage, /Setup does not contain or install a wallet service/);
  assert.match(legalPage, /provider\s+and value operations remain unavailable/);
  assert.match(legalPage, /separately released wallet service/);
  assert.match(legalPage, /approval-gated/);
  assert.match(
    legalPage,
    /href="https:\/\/denuoweb\.com\/work\/hns-dane-browser-extension"/
  );
  assert.match(
    legalPage,
    /denuoweb\.com\/work\/hns-dane-browser-extension\/privacy/
  );
  assert.match(
    legalPage,
    /denuoweb\.com\/work\/hns-dane-browser-extension\/legal/
  );
  assert.match(legalPage, /script type="module" src="legal\.js"/);
  assert.doesNotMatch(legalPage, /<script(?![^>]*\bsrc=)[^>]*>/i);
  assert.doesNotMatch(legalScript, /chrome\.storage|localStorage|sessionStorage/);
});

test("the legal screen reads exact release documents from the extension package", async () => {
  assert.deepEqual(
    LEGAL_DOCUMENTS.map(({ id, path }) => [id, path]),
    [
      ["privacy", "PRIVACY.md"],
      ["license", "LICENSE"],
      ["notices", "THIRD_PARTY_NOTICES.txt"]
    ]
  );
  assert.match(buildScript, /cpSync\("LICENSE", `\$\{output\}\/LICENSE`\)/);
  assert.match(buildScript, /docs\/privacy-policy\.md[\s\S]*PRIVACY\.md/);
  assert.match(buildScript, /THIRD_PARTY_NOTICES\.txt/);

  const nodes = new Map([
    ["#legal-version", { textContent: "" }],
    ["#privacy-document", { textContent: "" }],
    ["#license-document", { textContent: "" }],
    ["#notices-document", { textContent: "" }],
    ["#privacy details[data-legal-document]", { open: false }]
  ]);
  const requested = [];
  await initializeLegalPage({
    runtime: {
      getManifest: () => ({ version: "0.6.0" }),
      getURL: (path) => `chrome-extension://test/${path}`
    },
    documentObject: { querySelector: (selector) => nodes.get(selector) ?? null },
    fetchText: async (url) => {
      requested.push(url);
      return `contents of ${url}`;
    }
  });

  assert.equal(nodes.get("#legal-version").textContent, "version 0.6.0");
  assert.deepEqual(requested.sort(), [
    "chrome-extension://test/LICENSE",
    "chrome-extension://test/PRIVACY.md",
    "chrome-extension://test/THIRD_PARTY_NOTICES.txt"
  ]);
  assert.equal(nodes.get("#privacy details[data-legal-document]").open, true);
  assert.match(nodes.get("#privacy-document").textContent, /PRIVACY\.md/);
});

test("hash links open only known legal sections", () => {
  assert.equal(legalSectionFromHash("#license"), "license");
  assert.equal(legalSectionFromHash("agreement"), "agreement");
  assert.equal(legalSectionFromHash("#unknown"), "privacy");

  const details = { open: false };
  const documentObject = {
    querySelector: (selector) =>
      selector === "#notices details[data-legal-document]" ? details : null
  };
  assert.equal(openRequestedSection(documentObject, "#notices"), "notices");
  assert.equal(details.open, true);
});

test("setup, settings, and the popup all enter the internal legal screen", () => {
  assert.match(popup, /id="legal"[^>]*>Privacy &amp; Legal/);
  assert.match(popupScript, /runtime\.getURL\("src\/legal\.html"\)/);
  for (const page of [options, setup]) {
    assert.match(page, /href="legal\.html#privacy"/);
    assert.match(page, /href="legal\.html#agreement"/);
    assert.match(page, /href="legal\.html#notices"/);
    assert.doesNotMatch(page, /blob\/main\/(?:LICENSE|docs\/privacy-policy\.md)/);
  }
  assert.match(setup, /href="legal\.html#license"/);
});

test("privacy-sensitive fallback stays an explicit settings choice", () => {
  assert.equal(DEFAULT_POLICY.p2pDnsRelay, false);
  assert.equal(DEFAULT_POLICY.recursiveHnsDohUrl, "");
  assert.match(options, /id="p2p-dns-relay" type="checkbox"/);
  assert.match(options, /browser sends nothing[\s\S]*while\s+this\s+field is blank/i);
  assert.match(options, /Read the bundled privacy policy/);
});
