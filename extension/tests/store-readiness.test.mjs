import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";

const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
const storeReadme = readFileSync("store/README.md", "utf8");
const chromeListing = readFileSync("store/chrome/en-US.md", "utf8");
const edgeListing = readFileSync("store/edge/en-US.md", "utf8");
const operaListing = readFileSync("store/opera/en-US.md", "utf8");
const permissions = readFileSync("store/permission-justifications.md", "utf8");
const privacyDeclarations = readFileSync("store/privacy-declarations.md", "utf8");
const reviewerNotes = readFileSync("store/review-notes.md", "utf8");
const privacyPolicy = readFileSync("docs/privacy-policy.md", "utf8");

test("Chromium package and catalog artwork have exact required PNG dimensions", () => {
  for (const size of [16, 32, 48, 128]) {
    assert.deepEqual(pngDimensions(`extension/assets/icons/icon-${size}.png`), {
      width: size,
      height: size
    });
  }
  assert.deepEqual(pngDimensions("store/assets/chrome-edge/icon-300.png"), {
    width: 300,
    height: 300
  });
  assert.deepEqual(
    pngDimensions("store/assets/chrome-edge/promo-small-440x280.png"),
    { width: 440, height: 280 }
  );
  assert.deepEqual(
    pngDimensions("store/assets/chrome-edge/promo-marquee-1400x560.png"),
    { width: 1400, height: 560 }
  );

  const chromeScreenshots = readdirSync(
    "store/assets/chrome-edge/screenshots"
  ).filter((name) => name.endsWith(".png"));
  assert.equal(chromeScreenshots.length, 3);
  for (const name of chromeScreenshots) {
    assert.deepEqual(
      pngDimensions(`store/assets/chrome-edge/screenshots/${name}`),
      { width: 1280, height: 800 }
    );
  }

  const operaScreenshots = readdirSync("store/assets/opera/screenshots").filter(
    (name) => name.endsWith(".png")
  );
  assert.equal(operaScreenshots.length, 3);
  for (const name of operaScreenshots) {
    assert.deepEqual(
      pngDimensions(`store/assets/opera/screenshots/${name}`),
      { width: 612, height: 408 }
    );
  }
});

test("store copy covers every supported Chromium distribution and exact public links", () => {
  assert.ok(manifest.description.length <= 132);
  for (const browser of [
    "Google Chrome",
    "Brave",
    "Vivaldi",
    "Microsoft Edge",
    "Opera",
    "Chromium"
  ]) {
    assert.match(storeReadme, new RegExp(browser));
  }
  for (const listing of [chromeListing, edgeListing, operaListing]) {
    assert.match(listing, /handshake-rs\/hns-dane-browser-extension/);
    assert.match(listing, /HNS DANE Browser Setup/);
    assert.match(listing, /matching(?:\s+Rust)?\s+native host/i);
    assert.match(listing, /native(?: Rust)? host|native-host/i);
    assert.match(listing, /privacy/i);
    assert.match(listing, /github\.com\/sponsors\/denuoweb/);
    assert.match(listing, /-mv3-store\.zip/);
  }
  assert.match(storeReadme, /first-submission `-mv3-store\.zip`/);
  assert.match(storeReadme, /YouTube feature-video URL/);
  assert.match(chromeListing, /Localized promo video:[\s\S]*YouTube/);
  assert.match(chromeListing, /Donations do not unlock features/);
  assert.match(edgeListing, /Short description:/);
  assert.ok(
    edgeListing.split("## Description\n\n")[1].length >= 250,
    "Edge long description minimum"
  );
});

test("review and privacy drafts explain the native boundary and broad permissions", () => {
  assert.match(permissions, /Single purpose/);
  assert.match(permissions, /Remote code[\s\S]*`No\.`/);
  for (const permission of manifest.permissions) {
    assert.ok(permissions.includes(`\`${permission}\``), permission);
  }
  assert.match(permissions, /`<all_urls>`/);
  assert.match(reviewerNotes, /exact 32-character catalog extension ID/);
  assert.match(reviewerNotes, /HNS DANE Browser Setup/);
  assert.match(reviewerNotes, /does not scan browser profiles/);
  assert.match(reviewerNotes, /per-user local CA/);
  assert.match(reviewerNotes, /real public certificate/);
  assert.match(privacyDeclarations, /Web history \/ website activity/);
  assert.match(privacyDeclarations, /Cloudflare/);
  assert.match(privacyDeclarations, /Not sold/);
  assert.match(privacyPolicy, /Denuo Web, LLC/);
  assert.match(privacyPolicy, /cloudflare-dns\.com/);
  assert.match(privacyPolicy, /does not sell personal or\s+sensitive data/);
  assert.match(privacyPolicy, /Donations are optional/);
});

function pngDimensions(path) {
  const bytes = readFileSync(path);
  assert.equal(bytes.subarray(0, 8).toString("hex"), "89504e470d0a1a0a", path);
  assert.equal(bytes.subarray(12, 16).toString("ascii"), "IHDR", path);
  return {
    width: bytes.readUInt32BE(16),
    height: bytes.readUInt32BE(20)
  };
}
