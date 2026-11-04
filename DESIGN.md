---
name: SecureDrive
description: A light security workspace with visible cryptographic evidence.
colors:
  primary: "#245edb"
  primary-hover: "#194bbb"
  primary-soft: "#edf3ff"
  background: "#f4f6fa"
  surface: "#ffffff"
  surface-soft: "#f8fafd"
  ink: "#18283e"
  muted: "#5c6b80"
  border: "#dce3ed"
  navy: "#13243b"
  navy-soft: "#1e3553"
  nav-text: "#b8c8df"
  success: "#16704c"
  success-soft: "#edf8f1"
  danger: "#b5303d"
  danger-soft: "#fff1f2"
typography:
  headline:
    fontFamily: "Segoe UI, -apple-system, BlinkMacSystemFont, Arial, sans-serif"
    fontSize: "30px"
    fontWeight: 650
    lineHeight: 1.25
    letterSpacing: "-0.025em"
  title:
    fontFamily: "Segoe UI, -apple-system, BlinkMacSystemFont, Arial, sans-serif"
    fontSize: "17px"
    fontWeight: 650
    lineHeight: 1.25
  body:
    fontFamily: "Segoe UI, -apple-system, BlinkMacSystemFont, Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Segoe UI, -apple-system, BlinkMacSystemFont, Arial, sans-serif"
    fontSize: "12px"
    fontWeight: 600
  code:
    fontFamily: "Consolas, Liberation Mono, monospace"
    fontSize: "12px"
rounded:
  control: "7px"
  surface: "12px"
  badge: "5px"
spacing:
  small: "8px"
  medium: "16px"
  large: "24px"
  page: "36px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
    rounded: "{rounded.control}"
    padding: "9px 15px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.surface}"
  status-success:
    backgroundColor: "{colors.success-soft}"
    textColor: "{colors.success}"
    rounded: "{rounded.badge}"
    padding: "4px 8px"
---

# Design System: SecureDrive

## Overview

**Creative North Star: "Light security workspace"**

The user selected white surfaces, blue actions, and a familiar dashboard for a security project demonstration. The interface keeps file operations direct and makes cryptographic evidence easy to read. The implemented source of truth is [static/app.css](static/app.css), with shared icons and structure in the Jinja templates.

**Key Characteristics:**

- White work areas against a cool pale background.
- Deep navy navigation and blue primary actions.
- Real checks determine result colors.
- Familiar forms, readable evidence, and responsive tables.

## Colors

Blue identifies actions and selection. Navy anchors the navigation and authentication introduction. White and cool neutrals separate the workspace, tables, and code samples. Green and red communicate successful and failed checks; general server flash messages retain a neutral informational treatment.

**The Evidence Rule.** A security mechanism label names implemented technology; a verified status requires a result from the server.

## Typography

The system UI stack handles headings, controls, and prose. Monospace is reserved for hashes, signatures, byte samples, and technical identifiers. Main headings reduce to 26px on compact screens. Panel titles use 15px; helper text uses 11–12px. Numeric tables use tabular figures. The authentication introduction uses a 44px heading at full desktop width.

**The Readable Data Rule.** Preserve full cryptographic values with wrapping. Mobile chart lettering keeps its scale inside a scrollable plot instead of shrinking to fit.

## Layout

Desktop uses a fixed 232px navigation rail and a 72px top bar. Main content has a 1512px maximum width and 36px horizontal padding. Below 1200px, the rail narrows to 214px and content padding becomes 26px. Below 900px, navigation moves above the workspace. Below 650px, navigation forms two columns and content padding becomes 18px.

File tables scroll within named, keyboard-focusable regions. Compact layouts show an explicit scrolling instruction. Inspection panels stack on small screens. Performance charts use one column below 1200px and retain a 600px plot width below 650px, with a visible cue and keyboard-accessible scrolling.

## Elevation & Depth

Surfaces use tonal separation and thin borders. There are no decorative drop shadows. Dark navigation, a pale canvas, and white work areas establish the hierarchy.

## Shapes

Panels have softly rounded corners, controls smaller corners, and status badges compact corners. Icons use a consistent 24-unit SVG grid and 1.7-unit stroke. Native checkboxes and file selection retain familiar browser behavior.

## Components

Primary buttons have a 42px minimum height, blue background, and white text. Secondary buttons use a white surface and quiet blue border. Destructive actions use red text, a red hover tint, and the existing confirmation dialog. Authentication buttons and inputs are at least 46px high.

Fields have visible labels, a white fill, and a thin border. Keyboard focus uses a 3px blue outline with a 3px offset. Selection, carets, checkbox accents, and scrollbars follow the palette. Color transitions last 160ms and are removed when reduced motion is requested.

Navigation uses icon-and-text links, a filled current location, and a separate account area. The algorithm strip presents encryption, fingerprints, and signatures. Inspection uses paired plaintext and ciphertext panels, followed by the unchanged result tables.

## Do's and Don'ts

- Do reuse the shared stylesheet and SVG icon macro.
- Do preserve visible labels, keyboard focus, and explicit compact-table scrolling cues.
- Do derive file counts, statuses, and measurements from real application values.
- Don't add unsupported certification or end-to-end encryption claims.
- Don't replace working forms, routes, field names, CSRF tokens, or security checks as part of styling.
- Don't add external UI dependencies for these existing components.
