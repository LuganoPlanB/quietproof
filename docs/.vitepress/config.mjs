import { defineConfig } from "vitepress";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { searchForWorkspaceRoot } from "vite";
import { secureHtml } from './security.mjs';
import { wasmAsset } from './wasm.mjs';

const projectRoot = fileURLToPath(new URL("../..", import.meta.url));
const siteBase = process.env.DOCS_BASE || "/";

export default defineConfig({
  base: siteBase,
  // Local-search numeric IDs depend on insertion order. Serial indexing keeps
  // the search index, dependent JS filenames and CSP hashes reproducible.
  buildConcurrency: 1,
  lang: "en",
  title: "QuietProof",
  titleTemplate: ":title · QuietProof",
  description:
    "Prove control of P2WPKH bitcoin without revealing private keys or compressed public keys.",
  cleanUrls: true,
  lastUpdated: true,
  transformHtml: secureHtml,
  head: [
    ["meta", { name: "theme-color", content: "#fffefa" }],
    ["link", { rel: "icon", href: `${siteBase}quietproof-mark.svg`, type: "image/svg+xml" }],
  ],
  markdown: {
    config(md) {
      md.renderer.rules.table_open = (tokens, index, options, env, renderer) => {
        tokens[index].attrSet("tabindex", "0");
        return renderer.renderToken(tokens, index, options);
      };

      md.core.ruler.after("inline", "quietproof-included-doc-links", (state) => {
        const sourcePath = state.env.path || "";
        const rewrites =
          sourcePath.endsWith("technical/pokc.md")
            ? new Map([
                ["README.md", "/technical/architecture"],
                ["./README", "/technical/architecture"],
                ["docs/security.md", "/security"],
                ["./docs/security", "/security"],
                ["spec/README.md", "/technical/sage"],
                ["./spec/README", "/technical/sage"],
              ])
            : sourcePath.endsWith("security.md")
              ? new Map([
                  ["../spec/quietproof-v1.md", "/technical/protocol"],
                  ["./../spec/quietproof-v1", "/technical/protocol"],
                ])
              : null;

        if (!rewrites) return;

        for (const token of state.tokens) {
          if (token.type !== "inline" || !token.children) continue;
          for (const child of token.children) {
            if (child.type !== "link_open") continue;
            const hrefIndex = child.attrIndex("href");
            if (hrefIndex < 0) continue;
            const href = child.attrs[hrefIndex][1];
            if (rewrites.has(href)) child.attrs[hrefIndex][1] = rewrites.get(href);
          }
        }
      });
    },
  },
  vite: {
    plugins: [wasmAsset(projectRoot, siteBase)],
    server: {
      fs: {
        allow: [searchForWorkspaceRoot(projectRoot), resolve(projectRoot, "../vite-theme")],
      },
    },
  },
  themeConfig: {
    logo: { src: "/quietproof-mark.svg", alt: "QuietProof" },
    siteTitle: "QuietProof",
    nav: [
      { text: "Create a request", link: "/tool" },
      { text: "What it proves", link: "/what-it-proves" },
      { text: "Use cases", link: "/use-cases" },
      { text: "Guides", link: "/guide/" },
      { text: "Technical reference", link: "/technical/architecture" },
    ],
    sidebar: [
      {
        text: "Start here",
        items: [
          { text: "QuietProof in plain language", link: "/what-it-proves" },
          { text: "Where it can help", link: "/use-cases" },
          { text: "Limits and trust", link: "/limitations" },
          { text: "Glossary", link: "/glossary" },
        ],
      },
      {
        text: "Practical guides",
        items: [
          { text: "Guide overview", link: "/guide/" },
          { text: "Browser request and verifier", link: "/guide/browser-tool" },
          { text: "How a proof works", link: "/guide/how-it-works" },
          { text: "Auditor workflow", link: "/guide/auditor-workflow" },
          { text: "Build and try it", link: "/guide/getting-started" },
          { text: "Operations", link: "/operations" },
          { text: "Linux releases", link: "/releases" },
        ],
      },
      {
        text: "Technical reference",
        collapsed: false,
        items: [
          { text: "Architecture", link: "/technical/architecture" },
          { text: "PoKC circuit", link: "/technical/pokc" },
          { text: "P2SH 2-of-3 circuit", link: "/technical/p2sh-multisig" },
          { text: "Normative v1 protocol", link: "/technical/protocol" },
          { text: "Sage reference model", link: "/technical/sage" },
          { text: "Security claim matrix", link: "/security" },
          { text: "Performance", link: "/performance" },
        ],
      },
    ],
    search: {
      provider: "local",
      options: {
        detailedView: true,
        miniSearch: {
          searchOptions: { fuzzy: 0.2, prefix: true },
        },
      },
    },
    socialLinks: [
      { icon: "github", link: "https://github.com/LuganoPlanB/quietproof" },
    ],
    outline: { level: [2, 3], label: "On this page" },
    docFooter: { prev: "Previous", next: "Next" },
    lastUpdated: { text: "Last updated" },
    footer: {
      message: "Software licensed under the GNU General Public License v3 (GPLv3+).",
      copyright: "QuietProof is Copyright (C) 2026 by the Plan ₿ Foundation.",
    },
  },
});
