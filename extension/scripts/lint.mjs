import { execFileSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";

const roots = ["extension/src", "extension/scripts", "extension/tests"];
for (const root of roots) {
  for (const path of javascriptFiles(root)) {
    execFileSync(process.execPath, ["--check", path], { stdio: "inherit" });
  }
}

function javascriptFiles(root) {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) files.push(...javascriptFiles(path));
    if (entry.isFile() && /\.(?:js|mjs)$/.test(entry.name)) files.push(path);
  }
  return files.sort();
}
