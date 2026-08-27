# Design System: QuietProof Documentation

## Overview

QuietProof adopts the Lugano Plan B shared Vite theme from `../vite-theme` as its visual source of truth. Its scene is a careful conversation between an auditor and a custodian in a well-lit office: serious, private, and calm rather than secretive or theatrical.

The site uses the theme’s “Civic Digital Commons” direction—white-first civic clarity, navy typography, blue structure, and small electric connective details. Dark mode remains a supported preference. QuietProof-specific styling should extend the package through local CSS variables and namespaced components; it must not fork or duplicate the upstream theme contract.

## Color

- Use the shared theme’s Warm Canvas, Civic Ink, Lugano Night, Civic Sky, Commons Gold, and electric gradient tokens unchanged.
- Let blue communicate structure and trust. Reserve the electric gradient for proof-flow connections, focus signals, and compact brand marks.
- Use explicit labels and symbols in addition to color for positive claims, limitations, warnings, and unsupported states.
- Maintain WCAG AA text contrast in both theme modes.

## Typography

- Inherit the Plan B theme’s existing sans-serif stack to preserve shared identity.
- Use decisive, balanced headings and measured prose capped near 70 characters.
- Keep the landing page conversational. Introduce technical vocabulary in short definition blocks before using it freely.
- Use monospace only for commands, encodings, identifiers, and protocol data—not as the project’s brand voice.

## Layout

- The documentation uses VitePress navigation, local search, sidebars, outlines, and code blocks.
- The home page has a custom narrative layout rather than the default feature-card grid.
- The opening sequence is: core promise, operating profile, practical applications, challenge flow, two-key opportunity, and a clear path into technical documentation.
- Use the upstream `planb-*` shell, panel, action, and content classes where their semantics fit. Add local `quietproof-*` classes only for domain-specific diagrams and narrative layouts.
- Desktop layouts may pair an operating explanation with technical data. Mobile layouts return to natural document order without CSS reordering and keep wide tables locally scrollable.

## Components

### Operating profile

The first section after the hero gives dated, hardware-specific proof timing and size observations, the public and private inputs, the proof and verifier outputs, and the workload boundary. It must distinguish indicative measurements from requirements and explain why v1 suits discrete attestations rather than transaction-path or high-frequency processing.

### Challenge flow

A four-stage ordered sequence—challenge, private proof, verification, application decision—makes freshness and separation of responsibilities explicit. The sequence remains understandable without animation.

### Use-case index

Group applications by the job being done: custody and audit, qualification before a deal, private continuity, and collaborative protocols. Avoid a wall of identical cards; use strong section groupings and varied supporting examples.

### Technical depth marker

Pages state their intended depth using plain labels such as “Start here,” “Practical guide,” or “Protocol reference.” These labels aid orientation and are not repeated decorative eyebrows.

## Interaction and Motion

- Keep navigation and theme switching native to VitePress.
- Use short color, underline, and transform transitions for interactive feedback only.
- Do not hide content pending animation. Disable non-essential movement under `prefers-reduced-motion: reduce`.
- Provide a visible skip link, strong `:focus-visible` styles, and comfortable minimum target sizes.

## Content Rules

- Prefer “prove control of a Bitcoin spend key” over “prove ownership of Bitcoin.”
- Say “P2WPKH witness program” in technical material; introduce it up front as “the fingerprint embedded in a common kind of Bitcoin address.”
- Always distinguish proof verification from chain-state verification.
- Always state that key access could be shared or temporary and that QuietProof does not establish exclusive control.
- Link the full operations, security, performance, circuit, Sage, and normative specification pages from the primary documentation navigation.
