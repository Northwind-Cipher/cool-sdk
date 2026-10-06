# Brag Plan: CooL × Edgeless Systems Contrast

## What is this app?

CooL is an SDK that turns an AI change — a prompt edit, a model bump, a widened
agent permission — into a signed, offline-verifiable receipt. The new work binds
that receipt to an **Edgeless Systems Contrast** confidential Kubernetes
workload, so the receipt proves not only *what changed* but *which attested
workload produced it*.

## The angle

**Four forgeries, all rejected.**

The product is a verifier, so the most honest and most watchable thing it does is
*refuse*. Most security videos show a green checkmark and ask you to trust it.
This one shows the green checkmarks and then spends half its runtime trying to
break its own evidence — a stolen credential, a rebuilt image, a Coordinator
nobody attested — and failing, on camera.

The restraint is the pitch. The video ends on the thing it *won't* claim.

## Hook (first 2-3 seconds)

Black. One line of monospace, typed:

```
$ npm run demo:contrast
```

Then a single hard line in large type: **"Prove it."** — because that is what a
verifier is for, and it earns the next twenty seconds without a single adjective.

## Key moments (the middle)

- **The identity is read, not configured.** `platform / intel-tdx`, the policy
  hash, MRTD — pulled out of the Coordinator-issued mesh certificate. The line
  that matters: *not out of configuration*.
- **Four AI changes, sealed.** model → prompt → agent-permission → params,
  arriving one by one as log leaves 0,1,2,3. One transparency log, so order is
  provable.
- **Four forgeries, rejected.** The centrepiece. Each attack named, each
  verdict `workload=fail`, in red, one after another.

## Outro / punchline

Two beats. First the proof that was missing until now — **Verified on real Intel
TDX**, with the actual verdict underneath (`attestation pass · enclave pass ·
witnesses pass`) and where it ran (Phala Cloud, two CVMs, quotes verified against
`intel-dcap`). Then the line most products would cut:

> Not claimed: that the Contrast adapter has run on hardware.

The boundary is deliberately precise rather than modest: the evidence model IS
proven on silicon; the Contrast adapter is not. A system that will not round its
own evidence up is one whose `pass` means something. That is the brag.

## User flow worth showing

Entry → key action → result, straight from `examples/contrast/demo.mjs`:

1. **Entry** — `npm run demo:contrast` opens a workload and reads its Contrast
   identity out of `/contrast/tls-config/certChain.pem`.
2. **Key action** — four AI changes are sealed into one transparency log inside
   the confidential workload.
3. **Result** — an independent verifier returns a verdict per record, and then
   rejects four deliberate forgeries.

The terminal *is* the product here. This is a CLI and an SDK; there is no
landing page to recreate, and a recreated dashboard would be less true than the
actual stdout.

## Tone

- **Preset:** `polished`
- **Creative direction:** a quiet proof, not a pitch — the restraint is the product
- **Interpretation:** four scenes, long holds, slow crossfades. No exclamation
  marks, no swooshes, no stat-card confetti. Type enters fast and then sits
  still. The only "loud" moment is four red failures in a row, and they are loud
  because everything around them is calm.

## Format: landscape — 1920x1080
## Duration: 21s target

## Visual identity (from the project)

Taken from `assets/hero.svg` and `src/cli/ui/app.html`.

- **Background:** `#0b0f14`
- **Accent (pass):** `#7ee2a8`
- **Accent deep:** `#1f6f43`
- **Text:** `#e6edf3`
- **Muted:** `#8b949e`
- **Fail:** `#e5534b`
- **Display font:** system sans — `-apple-system, "Segoe UI", Roboto, system-ui`
- **Body/mono font:** `ui-monospace, "JetBrains Mono", Consolas, monospace`
- **Strongest visual element:** the terminal verdict rows — `✓ … workload=pass`
  in green against `✗ … workload=fail` in red. The product's own output is the
  design.

## Share copy (draft)

Built a cryptographic binding between CooL receipts and Edgeless Contrast
confidential workloads — a receipt now proves which attested workload produced
it. Then spent half the demo trying to forge one. Four attacks, four rejections.

## Audio direction

- **Role:** low professional bed with restrained motion-matched accents
- **Music:** `happy-beats-business-moves-vol-9` or `vol-1` — whichever reads
  calmer; needs to sit *under* the piece, never drive it
- **Music treatment:** fade in over ~0.8s, hold low (roughly -18 to -14 dB
  under the accents), duck slightly under the forgery sequence so the failures
  land dry, fade out across the final card
- **Music cue guidance:** read the bundled preset from `assets/music/cues/` at
  composition time. Target a strong cue for (a) the hook line settling and
  (b) the first red `workload=fail`. For the four sealed changes and the four
  forgeries, use a beat-grid window but hold each line to the readability floor —
  snap to every other beat rather than every beat, because these are text rows,
  not accents.
- **Audio-reactive treatment:** subtle — the terminal's border glow may breathe
  with music energy. No waveform bars, no pulsing type.
- **SFX posture:** sparse. A key-tick cluster on the typed command, one soft
  interface tick per sealed change, one dry low impact per rejection. Nothing
  cartoonish; this is a security product.
- **Audio-coupled moments:** the typed `$ npm run demo:contrast`; the four
  sealed changes arriving one by one; the four red rejections arriving one by
  one; the final honest line landing in near-silence.
- **Restraint rule:** no riser, no whoosh, no cymbal swell, and **no triumphant
  sting on the final card** — the last card is a disclaimer, and scoring it like
  a win would undercut the entire point of the video.

## Storyboard

### Scene 1 — Prove it — 4.0s

Black `#0b0f14`. A monospace prompt types at centre-left: `$ npm run
demo:contrast`, cursor blinking. It settles, then the display line arrives large
and centred: **Prove it.** Beneath it, small and muted:
`CooL × Edgeless Systems Contrast`.

Sequential/interaction: yes — the command types character by character, then the
headline cuts in after it settles.
Audio intent: quiet, a little tense. The bed starts almost inaudible.
Audio-coupled idea: key ticks under the typing; one soft tick as the headline lands.
Music: low, sparse entry.
Transition mood: soft → Scene 2

### Scene 2 — Read, not configured — 5.0s

A terminal panel. Real rows from the demo, arriving as a short stack:

```
platform              contrast / intel-tdx
workload              ai-service
policy hash           f04dfba7241ec8ca…
MRTD                  a27518a57994c0ec…
```

Then one muted caption settles under the panel and **holds**:
*Read out of the Coordinator-issued mesh certificate — not out of configuration.*

Sequential/interaction: yes — four rows arrive one by one, then the caption.
Hold the caption at least 1.4s; it is the thesis of the scene.
Audio intent: steady, procedural. The bed establishes.
Audio-coupled idea: one soft interface tick per row.
Transition mood: clean → Scene 3

### Scene 3 — Four changes, four forgeries — 7.5s

The centrepiece, in two halves on one continuous terminal.

**First half (~3s):** four green rows arrive, one per AI change, with their log
leaf index:

```
✓ model              billing/refund-agent#model          leaf 0
✓ prompt             billing/refund-agent#system         leaf 1
✓ agent-permission   billing/refund-agent#tools          leaf 2
✓ params             billing/refund-agent#temperature    leaf 3
```

**Second half (~4.5s):** the panel's accent shifts and four red rows arrive,
each one a named attack:

```
✗ tampered change                     workload=pass  signature=fail
✗ another workload's credential       workload=fail
✗ a Coordinator nobody attested       workload=fail
✗ a rebuilt image                     workload=fail
```

Sequential/interaction: yes — eight rows total, arriving one by one. Snap to
every *other* beat so each row holds ~0.5-0.6s settled; these are readable text,
not accents.
Audio intent: the green half is even and calm; the red half goes drier and
slightly quieter, each failure a dull low hit rather than an alarm.
Audio-coupled idea: soft tick per green row; one dry low impact per red row.
Transition mood: clean → Scene 4

### Scene 4 — What it will not claim — 4.5s

The terminal clears to the flat background. Centred, in sequence:

- **152 tests passing** (large, green accent) with `33 for this integration` small beneath
- a thin rule
- the honest line, amber-muted and held longest:
  *Not claimed: that any hardware was involved.*
- then, small and quiet: `npm run demo:contrast` ·
  `github.com/Northwind-Cipher/cool-sdk`
- footer, barely there: `Contrast is a product of Edgeless Systems GmbH · no endorsement implied`

Sequential/interaction: yes — three beats, each held. The honest line gets the
longest hold in the whole video (≥1.6s).
Audio intent: the bed thins out and fades. The final line sits in near-silence.
Audio-coupled idea: none — deliberately. No sting.
Transition mood: slow fade to black → end

**Scene durations:** 4.0 + 5.0 + 7.5 + 4.5 = **21.0s** ✓ (within 15-25s)

**Music mood for this video:** restrained, professional, under everything
**Audio summary:** a low bed enters under a typed command, holds steady through
the identity and the sealed changes, goes dry and quiet under four rejections,
and fades out entirely before the disclaimer — so the last thing the viewer
hears is nothing, which is the point.
