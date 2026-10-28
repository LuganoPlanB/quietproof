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
    "docs/guide/browser-tool.md",
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
    "Separate proofs in application workflows",
    "Collaborative Bitcoin protocols",
    "future directions",
  ]) {
    assert.match(useCases, new RegExp(heading, "i"));
  }

  assert.match(useCases, /not current QuietProof claims/);
  assert.match(useCases, /All outputs share one key hash/);
});

test("site navigation exposes operations, security, performance, circuit, and protocol docs", () => {
  const config = read("docs/.vitepress/config.mjs");

  for (const route of [
    "/operations",
    "/guide/browser-tool",
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

test("GitHub Pages deployment is reproducible and base-path aware", () => {
  const config = read("docs/.vitepress/config.mjs");
  const home = read("docs/.vitepress/theme/components/HomePage.vue");
  const workflow = read(".github/workflows/deploy-pages.yml");
  const qualification = read(".github/workflows/test.yml");

  assert.match(config, /const siteBase = process\.env\.DOCS_BASE \|\| "\/"/);
  assert.match(config, /base: siteBase/);
  assert.match(config, /href: `\$\{siteBase\}quietproof-mark\.svg`/);
  assert.match(home, /import \{ withBase \} from "vitepress"/);
  assert.doesNotMatch(home, /(?<!:)href="\//);

  assert.match(qualification, /repository: LuganoPlanB\/vite-theme/);
  assert.match(qualification, /ref: a7fde3404a5e2b32bf57b4bcb99337479c5c75b2/);
  assert.match(qualification, /npm ci/);
  assert.match(qualification, /scripts\/qualify_static\.py/);
  assert.match(qualification, /scripts\/install_wasi\.py/);
  assert.doesNotMatch(workflow, /uses: \.\/\.github\/workflows\/test.yml/);
  assert.match(workflow, /workflow_run:/);
  assert.match(workflow, /workflows: \[Tests\]/);
  assert.match(workflow, /github\.event\.workflow_run\.event == 'push'/);
  assert.match(workflow, /run-id: \$\{\{ steps\.source\.outputs\.run_id \}\}/);
  assert.match(workflow, /scripts\/check_pages_artifact\.py/);
  assert.match(workflow, /EXPECTED_BASE: \$\{\{ steps\.pages\.outputs\.base_path \}\}\//);
  assert.match(workflow, /path: checked-site/);
  assert.match(workflow, /pages: write/);
  assert.match(workflow, /id-token: write/);
});
