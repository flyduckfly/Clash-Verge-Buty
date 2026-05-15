# Project Structure & Naming Conventions

## 1) Top-level directory responsibilities

- `src/`: Frontend web UI source (React + TypeScript).
- `src-tauri/`: Tauri/Rust backend, app packaging metadata, platform build resources.
- `scripts/`: Build/check/release helper scripts (Node `.mjs`).
- `.github/`: CI workflows and custom Linux build action resources.
- `.husky/`: Git hook bootstrap and local pre-commit entrypoints.
- `docs/`: Documentation and operational guides.
- `patches/`: Local dependency patch files (reserved for package patching workflows).

## 2) Frontend (`src/`) layout conventions

Recommended structure (aligned with current repository organization):

- `src/pages/`: route-level page entries.
- `src/components/`: reusable UI components, grouped by domain (`layout`, `proxy`, `setting`, etc.).
- `src/hooks/`: shared composable hooks.
- `src/services/`: API wrappers, command bridge and state/service adapters.
- `src/utils/`: pure helper utilities.
- `src/assets/`: static frontend assets (images/fonts/styles).
- `src/locales/`: i18n dictionaries.

Placement rules:

- Route components go under `src/pages`.
- Reusable presentational/business components go under `src/components/<domain>`.
- Side-effect and fetch orchestration hooks go in `src/hooks`.
- Tauri invoke adapters / network calls / service clients go in `src/services`.
- General-purpose helpers with no UI state go in `src/utils`.

## 3) Backend (`src-tauri/`) layout conventions

- `src-tauri/src/`: Rust application code.
  - `core/`: lifecycle orchestration, runtime management, diagnostics, service/tray/hotkey coordination.
  - `config/`: config schema/load/save/patch/runtime types.
  - `feat/`: platform integration features (proxy patching, system proxy, clash/verge patching).
  - `enhance/`: enhancement logic (merge/tun/script/chain/field helpers).
  - `utils/`: filesystem, init, template and support utilities.
- `src-tauri/windows-service-src/`: Windows service source project (must remain source-only).
- `src-tauri/icons/`: application/tray/installer icon assets referenced by Tauri config.
- `src-tauri/template/`: installer/desktop templates referenced by platform Tauri config.
- `src-tauri/tauri*.conf.json`: base and platform-specific Tauri configuration.

## 4) Rust naming rules

- File names: `snake_case.rs`.
- Directory names: `snake_case`.
- Module names should match file names and avoid mixed naming styles.
- Keep `mod.rs` only when needed for module aggregation.

## 5) TypeScript/React naming rules

To match current repository dominant style:

- React component files: **`kebab-case.tsx`** (current dominant pattern).
- Generic TS utility/service files: **`kebab-case.ts`**.
- Hooks: **`use-xxx.ts`** (current dominant pattern, continue consistently).
- API/service files: prefer `xxx-service.ts` for new domain-specific services; keep existing `api.ts`/`cmds.ts` unless refactoring in dedicated PR.
- Store/state files: `xxx-store.ts` (for new additions).
- Types: prefer `xxx.types.ts` for new domain-specific type files; avoid adding new global `*.d.ts` unless required.

## 6) `scripts` / `.github` / `docs` / `patches` naming rules

- Workflow files: `kebab-case.yml`.
- Script files: `kebab-case.mjs` / `kebab-case.ts` / `kebab-case.sh`.
- Docs files: `kebab-case.md` (except canonical files like `README.md`, `LICENSE`, `CONTRIBUTING.md`).
- Patch files: descriptive `kebab-case.patch` naming (include target context when possible).

## 7) Directories that must not commit build artifacts

Never commit generated binaries/build outputs into repository source trees, including:

- `src-tauri/target/`
- `src-tauri/windows-service-src/target/`
- frontend build outputs (e.g. `dist/` if generated locally)
- temporary staging binaries in `src-tauri/local-binaries/windows-service-bin/` (runtime/CI staging only)

`src-tauri/local-binaries/windows-service-bin/` may exist as a staging path for scripts/CI, but its executable outputs should not be committed.

## 8) Where to place newly added files

- New page route: `src/pages/`.
- Reusable UI module: `src/components/<domain>/`.
- Shared hook: `src/hooks/`.
- New frontend integration adapter/client: `src/services/`.
- Cross-cutting helper (frontend): `src/utils/`.
- Backend core orchestration/service logic: `src-tauri/src/core/`.
- Backend feature integration logic: `src-tauri/src/feat/`.
- Backend enhancement logic: `src-tauri/src/enhance/`.
- Backend config/type/runtime config logic: `src-tauri/src/config/`.
- Backend generic helper: `src-tauri/src/utils/`.

## 9) Staged normalization strategy

- Phase 1 (low risk): naming standard documentation, empty/unused directory cleanup after reference validation.
- Phase 2 (medium risk): non-behavioral rename-only PRs (single domain per PR, with import/path updates).
- Phase 3 (higher risk): structural refactors that move business modules.

