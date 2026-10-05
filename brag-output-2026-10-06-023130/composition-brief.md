# Hyperframes Composition Brief: CooL × Edgeless Systems Contrast

## Objective

Create a short launch-style brag video for the CooL × Contrast integration — a
cryptographic binding between CooL's verifiable AI-change receipts and an
Edgeless Systems Contrast confidential Kubernetes workload.

## Output

- Composition directory: `brag-output-2026-10-06-023130/composition/`
- Rendered video: `brag-output-2026-10-06-023130/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 23.2s

## Source Material

- Project root: `f:/cool sdk/cool-sdk-final/cool-sdk`
- Primary files read: `README.md`, `docs/contrast.md`, `examples/contrast/demo.mjs`,
  `src/contrast/*.ts`, `assets/hero.svg`, `src/cli/ui/app.html`
- Product name: CooL (`cool-nwc`) × Edgeless Systems Contrast
- Tagline / strongest claim: *A receipt from one workload cannot be presented as
  another's.*
- Key UI or visual moment to recreate: **the terminal output of
  `npm run demo:contrast`** — this is a CLI and an SDK, so the real stdout *is*
  the product surface. There is no landing page, and a recreated dashboard would
  be less true than the actual output.
- Copy that must appear verbatim (all of it is real output or real doc text):
  - `$ npm run demo:contrast`
  - `platform              contrast / intel-tdx`
  - `policy hash           f04dfba7241ec8ca…`
  - `MRTD                  a27518a57994c0ec…`
  - "Read out of the Coordinator-issued mesh certificate — not out of configuration."
  - `✓ model              billing/refund-agent#model          leaf 0`
  - `✓ prompt             billing/refund-agent#system         leaf 1`
  - `✓ agent-permission   billing/refund-agent#tools          leaf 2`
  - `✓ params             billing/refund-agent#temperature    leaf 3`
  - `✗ another workload's credential          workload=fail`
  - `✗ a Coordinator nobody attested          workload=fail`
  - `✗ a rebuilt image                        workload=fail`
  - `152 tests passing`
  - "Not claimed: that any hardware was involved."

## Creative Direction

- **Tone preset:** `polished`
- **Creative direction:** a quiet proof, not a pitch — the restraint is the product
- **Interpretation:** four scenes, long holds, slow crossfades. No exclamation
  marks, no swooshes, no confetti. Type enters fast and then sits still. The
  only loud passage is four red failures in a row, and they read as loud because
  everything around them is calm.
- **Angle:** *Four forgeries, all rejected.* The product is a verifier, so the
  most honest and most watchable thing it does is refuse. Most security videos
  show a green checkmark and ask you to trust it; this one shows the green
  checkmarks and then spends half its runtime trying to break its own evidence
  — a stolen credential, a rebuilt image, a Coordinator nobody attested — and
  failing, on camera.
- **Hook:** a monospace prompt types `$ npm run demo:contrast`, then one display
  line: **Prove it.**
- **Outro / punchline:** `152 tests passing`, then the line most products would
  cut: *Not claimed: that any hardware was involved.*
- **Avoid:**
  - Generic SaaS language
  - Abstract filler visuals
  - Unrelated visual redesign
  - Any triumphant sting on the final card — it is a disclaimer, not a win

## Visual Identity

Taken from the project's own `assets/hero.svg` and `src/cli/ui/app.html`.

- **Background:** `#0b0f14`
- **Text:** `#e6edf3`
- **Muted:** `#8b949e`
- **Accent (pass):** `#7ee2a8`
- **Accent deep:** `#1f6f43`
- **Fail:** `#e5534b`
- **Display font:** system sans stack — `-apple-system, "Segoe UI", Roboto, system-ui`
- **Body/mono font:** `ui-monospace, "JetBrains Mono", Consolas, monospace`
- **Visual references:** the terminal verdict rows; the pass/fail colour pairing;
  the hero SVG's dark-with-green-accent palette

No `@font-face` is declared — the composition uses only generic/system stacks,
so the `font_family_without_font_face` lint rule does not apply.

## Storyboard

`brag-output-2026-10-06-023130/brag-plan.md` is the creative contract.

1. **Prove it** — 4.23s — typed command, then the display line, then the pairing.
2. **Read, not configured** — 5.27s — four real identity rows, then the thesis caption.
3. **Four changes, four forgeries** — 8.94s — four green rows, then four red rows.
4. **What it will not claim** — 4.73s — the test count, the honest line, the repo.

## Audio

- **Audio role:** low professional bed with restrained motion-matched accents
- **Audio arc:** the bed enters almost inaudibly under a typed command, holds
  steady through the identity and the sealed changes, goes dry and quieter under
  the four rejections, and fades out entirely before the disclaimer — so the
  last thing the viewer hears is nothing.
- **Music:** `assets/music/happy-beats-business-moves-vol-9-by-ende-dot-app.mp3`
  (114.84 BPM; chosen over vol-1 because its beat grid starts at 1.07s rather
  than 3.02s, which the 4s hook needs)
- **Music treatment:** fade in to a low bed, duck slightly under the forgery
  sequence, fade to silence across the final card. Never drives the piece.
- **Music cue guidance:** bundled preset
  `assets/music/happy-beats-business-moves-vol-9-by-ende-dot-app.music-cues.json`.
  - Strong-cue locks (3): **10.54s** green rows mid-arrival, **11.60s** green set
    completes, **12.65s** the first red failure — the dramatic beat of the video.
  - Beat-grid windows: green rows on consecutive beats
    `10.01 / 10.54 / 11.06 / 11.60` (0.52s apart — at the readability floor for
    these short rows, and the full set holds on screen for 1.05s after).
    Red rows on **every other** beat `12.65 / 13.70 / 14.76 / 15.81` (1.05s
    apart) because each names an attack and must be read; the full set then
    holds for 2.6s.
- **Audio-reactive treatment:** subtle — the terminal panel's border glow may
  breathe with music energy. No waveform bars, no pulsing type.
- **Audio-coupled moments:**
  - Scene 1 — typed `$ npm run demo:contrast` (key ticks), headline landing (one soft impact)
  - Scene 2 — four identity rows arriving one by one (soft tick each)
  - Scene 3 — four green rows (soft tick each); four red rows (one dry low impact each)
  - Scene 4 — deliberately silent; no sting
- **SFX selection guidance:** sparse and warm. Chosen from the skill's
  `sfx-analysis.md` "Safest General Picks", all **low high-frequency risk**
  because several repeat:
  - `assets/sfx/click_003.ogg` (0.01s) — typing ticks
  - `assets/sfx/rollover2.ogg` (0.06s) — row arrivals
  - `assets/sfx/impactSoft_medium_001.ogg` (0.18s, warm transient) — each rejection
  - `assets/sfx/impactSoft_medium_004.ogg` (0.15s, warm transient) — headline landing
- **Restraint rule:** no riser, no whoosh, no cymbal swell, and no sting on the
  final card.

## Hyperframes Instructions

Standalone monolithic composition (four scenes, one file) — the piece is short
and shares one terminal surface, so sub-compositions would add indirection
without buying reuse.

Requirements honoured:
- Shows real product output (the demo's actual stdout) — not a marketing mockup.
- All text held to the readability floor; red rows get 1.05s each.
- Duration 23.2s, within 15–25s.
- Music + SFX layer present; every `<audio>` carries an `id`.
- Initial transform states live inside `gsap.fromTo`, never in CSS, to avoid
  `gsap_css_transform_conflict`.
- No `visibility`/`autoAlpha` tweens on any `.clip`.
- `npx hyperframes check` must pass before render.
