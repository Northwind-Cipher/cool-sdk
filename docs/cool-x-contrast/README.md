# CooL × Edgeless Systems Contrast — deliverables

Everything for the CooL × Contrast integration in one folder: two documents in
PDF and Word, and the demo video.

> Contrast protects the AI workload while it runs. CooL produces independently
> verifiable evidence of what changed inside it, bound to that workload.

| File | What it is |
| --- | --- |
| [`CooL-x-Contrast-Technical-Documentation.pdf`](CooL-x-Contrast-Technical-Documentation.pdf) · [`.docx`](CooL-x-Contrast-Technical-Documentation.docx) | **21 pages.** Architecture, the key finding that Contrast attests by credential rather than by quote, the two-sided cryptographic binding, receipt format and backward compatibility, the eight verdict domains and their honesty rules, integration surface, deployment, trust model and threat table, the full test matrix, and a line-by-line citation of every Contrast behaviour relied on. |
| [`CooL-x-Contrast-Intersections.pdf`](CooL-x-Contrast-Intersections.pdf) · [`.docx`](CooL-x-Contrast-Intersections.docx) | **10 pages.** Where the two systems meet and why it pays both ways — the gap neither closes alone, a seven-row intersection map, what Contrast gains, what CooL gains, what the customer gains, the commercial shape, honest boundaries, and proposed next steps. |
| [`cool-contrast-demo.mp4`](cool-contrast-demo.mp4) | **23 seconds, 1080p.** The launch video: a typed `npm run demo:contrast`, the workload identity read out of the Coordinator-issued certificate, four AI changes sealed, then four forgeries rejected — and the line most products would cut. |
| [`cool-contrast-demo-poster.jpg`](cool-contrast-demo-poster.jpg) | Poster frame, also baked as frame 0 of the video so every platform's thumbnail picks it up. |
| [`share-copy.txt`](share-copy.txt) | A postable caption for the video. |

## How these were produced

Both documents are generated from **one content source**
([`tools/docs-build/`](../../tools/docs-build)), so the PDF and Word copies
cannot drift apart. The video is a [Hyperframes](https://www.npmjs.com/package/hyperframes)
composition built with the `/brag` workflow; its plan, composition brief and
source composition are kept in `brag-output-2026-10-06-023130/` at the
repository root.

```sh
cd tools/docs-build && npm install && npm run docs   # rebuild both documents
```

**On the video's audio.** The composition scores a music bed plus sparse motion-
matched SFX. The cut published here is rendered with the **music lane muted**
and the SFX intact: the SFX are Kenney (CC0), while the bundled music track's
licence terms are explicitly flagged as unverified-for-redistribution by the
tooling that ships it, and this repository is public. The scored cut renders
from the same composition by restoring the music automation lane.

## What these documents do not claim

Stated on the cover of each document and on the video's closing card, because a
verifier that will not round its own evidence up is the whole product:

- **No hardware run.** Nothing described has executed on Intel TDX or AMD
  SEV-SNP. The conformance fixtures carry a TDX quote constructed in software.
- **The Kubernetes manifests are unvalidated.** They are written against
  Contrast's current generator and have not been applied to a cluster.
- **CooL does not verify the hardware quote.** It verifies that the credential
  chains to a Coordinator root the reader pinned. A compromised Coordinator
  could certify an arbitrary workload — Contrast's own trust assumption, which
  CooL inherits and narrows by requiring the reader to attest the Coordinator
  independently.
- **No endorsement is implied.** Contrast is a product of Edgeless Systems GmbH,
  which has not reviewed this work. Every Contrast behaviour described is cited
  to public source and documentation.

See [`docs/contrast.md`](../contrast.md) §7 for exactly what was and was not
tested, and `npm run demo:contrast` to reproduce the demo in about ninety
seconds with no cluster.
