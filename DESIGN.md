# DD-WRT Telemetry — Enterprise SOC Dark Design System (DESIGN.md)

## 1. Visual Language & Overview
Enterprise SOC Dark is designed specifically for enterprise security operations centers (SOC), network operations centers (NOC), and infrastructure observability environments. It prioritizes low visual fatigue during extended low-light monitoring, high-density data representation, instantaneous anomaly detection, and unambiguous status attribution.

---

## 2. Color Palette & Tokens

### 2.1 Surfaces & Architecture
* **Canvas Background**: `#0b101b` (Deep Slate / Obsidian Navy)
* **Surface Background (Cards / Panels)**: `#121826` / `rgba(18, 24, 38, 0.95)`
* **Surface Header / Secondary**: `#182234`
* **Surface Elevated / Popover**: `#1f2c42`
* **Subtle Grid Overlay**: `radial-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px)` (16px grid)

### 2.2 Borders & Dividers
* **Primary Container Border**: `rgba(255, 255, 255, 0.08)` (1px solid `#1e293b`)
* **Active / Focus Border**: `rgba(56, 189, 248, 0.4)`
* **Table Row Divider**: `rgba(255, 255, 255, 0.04)`

### 2.3 Typography Colors (WCAG AA >= 4.5:1 Verified)
* **Primary Text (Headings, Key Numbers)**: `#f8fafc` (Slate 50)
* **Secondary Text (Labels, Sub-headers)**: `#b4c2d4` (~8.6:1 on `#121826`)
* **Muted / Metadata Text (IPs, Timestamps, Ports)**: `#94a3b8` (Slate 400, ~5.8:1 on `#121826`, ~6.1:1 on `#0e1420`)
* **Monospace Code / Value Highlight**: `#cbd5e1` (Slate 300)

### 2.4 Status & Telemetry Semantic Tokens
* **Allowed / Forwarded**:
  * Accent / Bar: `#38bdf8` (Vivid Sky Blue)
  * Badge Background: `rgba(56, 189, 248, 0.12)`
  * Badge Text / Border: `#38bdf8` / `rgba(56, 189, 248, 0.55)` (>= 3:1 non-text contrast)
* **Cached / Local Memory**:
  * Accent / Bar: `#34d399` (Mint Emerald)
  * Badge Background: `rgba(52, 211, 153, 0.12)`
  * Badge Text / Border: `#34d399` / `rgba(52, 211, 153, 0.55)`
* **Blocked / AdGuard / Threat Sinkhole**:
  * Accent / Bar: `#f43f5e` (Crimson Rose)
  * Badge Background: `rgba(244, 63, 94, 0.14)`
  * Badge Text / Border: `#f43f5e` / `rgba(244, 63, 94, 0.58)`
* **NXDOMAIN / DNS Failure**:
  * Accent / Bar: `#fbbf24` (Amber Gold)
  * Badge Background: `rgba(251, 191, 36, 0.12)`
  * Badge Text / Border: `#fbbf24` / `rgba(251, 191, 36, 0.55)`

### 2.5 Interactive & Brand Accents
* **Brand Primary (Buttons, Active Toggles)**: `#2563eb` (Enterprise Royal Blue)
* **Hover State**: `#1d4ed8`
* **Live Ingestion Active Glow**: `#10b981` (Pulse Dot)

---

## 3. Typography System

### 3.1 Font Families
* **Primary UI & Headings**: `Inter`, `-apple-system`, `BlinkMacSystemFont`, `Segoe UI`, `sans-serif`
* **Telemetry Data, Logs, IPs & Metrics**: `'JetBrains Mono'`, `'Fira Code'`, `'SF Mono'`, `monospace`

### 3.2 Scale & Hierarchy
* **App Title**: 16px / Semi-bold (600) / Tracking: `-0.01em`
* **Metric Stat Hero**: 36px / Bold (700) / Tabular figures / Monospace
* **Metric Stat Header**: 11px / Medium (500) / Uppercase / Letter spacing: `0.08em` / Color: Slate 400
* **Section Header**: 14px / Semi-bold (600) / Color: Slate 200
* **Table Header**: 10px / Semi-bold (600) / Uppercase / Letter spacing: `0.06em` / Color: Slate 400
* **Table Cell (Domain / Host)**: 12px / Monospace / Regular (400) / Color: Slate 200
* **Table Cell (IP / Timestamp)**: 11px / Monospace / Regular (400) / Color: Slate 500
* **Pill Badges**: 10px / Bold (700) / Uppercase / Letter spacing: `0.05em` / Padding: `2px 6px`

---

## 4. Layout & Grid Architecture

### 4.1 Page Framework
* **Container Width**: Max `1680px` (or full responsive 100vw desktop container), padded `24px` on all sides.
* **Vertical Rhythm**: `16px` consistent gap between rows and card modules.
* **Card Border Radius**: `8px` (`rounded-lg`) throughout for a sharp, utilitarian workstation profile.

### 4.2 Structural Sections
1. **Header Bar**:
   * Left: Router identity status orb, brand title (`DD-WRT Router / DNS Telemetry`), port chip (`Firewall :8788 ↗`), and log counters.
   * Right: Time range pill toggle (`15m`, `1h`, `6h`, `24h`, `7d`, `All`), `Hide PTR` toggle, `Live: 3s` interval picker, `CSV` export, and primary `Sync Router` button.
2. **KPI Summary Cards (4-Column Grid)**:
   * Total Queries (with `/m` rate chip)
   * AdGuard Blocked (with `%` blocked rate pill)
   * Cache Hit Rate (with absolute hit counter pill)
   * Active LAN Devices (with anomaly NX badge)
3. **Main Body (Split Columns - 70/30)**:
   * **Left Column (Primary Telemetry)**:
     * Stacked Bar Query Activity Timeline with legend and granular time axis.
     * Query Log Stream with search filter, status pills, and dense monospace tabular data.
   * **Right Column (Contextual Telemetry)**:
     * LAN Devices breakdown with multi-color segmented progress bars showing Allowed/Cached/Blocked/NX ratio per client.
     * Tabbed leaderboards: `Top Domains`, `Top Blocked`, `NXDOMAIN`.

---

## 5. UI Components & Patterns

### 5.1 Telemetry Cards
* Background: `#121826`
* Border: `1px solid rgba(255, 255, 255, 0.08)`
* Internal padding: `18px 20px`
* Shadow: `0 4px 16px -2px rgba(0, 0, 0, 0.4)`

### 5.2 Status Pills & Badges
* Rounded: `4px`
* Text: `10px` bold uppercase monospace
* Borders: 1px matching translucent border

### 5.3 Segmented Horizontal Client Bars
* Total width: 100%
* Height: `4px` to `6px`
* Stacked flex items with `border-radius: 9999px` ends and corresponding status colors (Sky Blue, Emerald, Rose, Amber).

### 5.4 Search & Input Fields
* Background: `#0e1420`
* Border: `1px solid rgba(255, 255, 255, 0.12)`
* Placeholder: `#64748b`
* Radius: `6px`
* Height: `32px`

---

## 6. Motion & Interactive Guidelines
* **Live Ingestion**: Subtle `1.5s` infinite ping on the green status orb in the header (automatically disabled under `prefers-reduced-motion: reduce`).
* **Hover Transitions**: `150ms ease-in-out` on buttons, table rows, and client list items.
* **Bar Hover**: Highlight bar segments with `opacity: 0.85` and trigger tabular tooltip.
* **Theme Toggle**: Both dashboards support a Dark / Light theme toggle persisted in `localStorage` (`ddwrt-theme`) with OS `prefers-color-scheme` detection and WCAG AA light tokens (`#f1f5f9` canvas, `#ffffff` surfaces, `#0f172a` primary ink, `#475569` metadata, and Sky-700/Emerald-700/Rose-700/Amber-700 status badges).
