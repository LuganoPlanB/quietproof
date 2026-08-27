import assert from "node:assert/strict";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const root = new URL("..", import.meta.url).pathname;
const read = (path) => readFileSync(join(root, path), "utf8");

test("VitePress consumes the sibling Plan B theme as a package", () => {
  const packageJson = JSON.parse(read("package.json"));
  const themeEntry = read("docs/.vitepress/theme/index.js");
  const layout = read("docs/.vitepress/theme/Layout.vue");

  assert.equal(packageJson.devDependencies["lugano-planb-vite-theme"], "file:../vite-theme");
  assert.match(themeEntry, /lugano-planb-vite-theme\/theme\.css/);
  assert.doesNotMatch(themeEntry, /\.\.\/\.\.\/\.\.\/vite-theme/);
  assert.equal(packageJson.scripts["docs:dev"], "vitepress dev docs");
  assert.equal(packageJson.scripts["docs:build"], "vitepress build docs");
  assert.match(layout, /dataset\.theme = dark \? "dark" : "light"/);
});

test("the approachable path and complete reference path are present", () => {
  const requiredPages = [
    "docs/index.md",
    "docs/what-it-proves.md",
    "docs/use-cases.md",
    "docs/limitations.md",
    "docs/glossary.md",
    "docs/guide/index.md",
    "docs/guide/how-it-works.md",
    "docs/guide/auditor-workflow.md",
    "docs/guide/getting-started.md",
    "docs/technical/architecture.md",
    "docs/technical/pokc.md",
    "docs/technical/protocol.md",
    "docs/technical/sage.md",
    "docs/operations.md",
    "docs/security.md",
    "docs/performance.md",
  ];

  for (const page of requiredPages) {
    assert.ok(statSync(join(root, page)).isFile(), `${page} should exist`);
  }

  assert.match(read("docs/technical/pokc.md"), /@include: \.\.\/\.\.\/pokc\.md/);
  assert.match(read("docs/technical/protocol.md"), /@include: \.\.\/\.\.\/spec\/quietproof-v1\.md/);
  assert.match(read("docs/technical/sage.md"), /@include: \.\.\/\.\.\/spec\/README\.md/);
});

test("the public explanation retains the capability and its boundary in the detailed guide", () => {
  const home = read("docs/.vitepress/theme/components/HomePage.vue");
  const explanation = read("docs/what-it-proves.md");

  assert.match(home, /Prove you control bitcoin\. Keep your keys quiet\./);
  assert.match(explanation, /does not establish:/i);
  assert.match(explanation, /Exclusive control/);
  assert.match(explanation, /not the whole system/);
});

test("the homepage gives a factual operating profile", () => {
  const home = read("docs/.vitepress/theme/components/HomePage.vue");

  assert.match(home, /Built for deliberate attestations/);
  assert.match(home, /not a\s+transaction path or a high-frequency request loop/);
  assert.match(home, /Observed end-to-end native API performance/);
  assert.match(home, /29\.892 s/);
  assert.match(home, /19\.899 s/);
  assert.match(home, /44\.71 MiB/);
  assert.match(home, /60\.200 s/);
  assert.match(home, /38\.967 s/);
  assert.match(home, /87\.04 MiB/);
  assert.match(home, /Public request/);
  assert.match(home, /Private prover input/);
  assert.match(home, /Proof artifact/);
  assert.match(home, /Verifier output/);
  assert.match(home, /scope="col"/);
  assert.doesNotMatch(home, /A careful claim, by design/);
});

test("use cases are grouped by human jobs and retain technical caveats", () => {
  const useCases = read("docs/use-cases.md");

  for (const heading of [
    "Custody and audit",
    "Qualification before a deal",
    "Private continuity and peer credit",
    "Collaborative Bitcoin protocols",
    "future directions",
  ]) {
    assert.match(useCases, new RegExp(heading, "i"));
  }

  assert.match(useCases, /not current QuietProof claims/);
  assert.match(useCases, /at most two distinct witness programs/);
});

test("site navigation exposes operations, security, performance, circuit, and protocol docs", () => {
  const config = read("docs/.vitepress/config.mjs");

  for (const route of [
    "/operations",
    "/security",
    "/performance",
    "/technical/pokc",
    "/technical/protocol",
    "/technical/sage",
  ]) {
    assert.ok(config.includes(`link: "${route}"`), `${route} should appear in navigation`);
  }

  assert.match(config, /attrSet\("tabindex", "0"\)/);
});
