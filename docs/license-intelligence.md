# License intelligence

License analysis is local, bounded, and conservative. It uses dependency metadata and lockfile evidence when available, then classifies the result as explicit, inherited, denied, review-required, or unknown.

Supported identifiers include SPDX-style labels when they are present in source metadata:
`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `GPL-2.0`, `GPL-3.0`, `LGPL`, `AGPL`, `MPL`, `EPL`, `CDDL`, `SSPL`, `proprietary`, and `unknown`.

The implementation reports:
- direct and transitive attribution
- license inventory summaries
- policy evaluation results
- explicit `UNKNOWN` states when metadata is incomplete

It never claims authority when the metadata does not support that conclusion.