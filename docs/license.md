# License intelligence status

Version 0.8.0 was the last release before license intelligence existed.
The current 0.9.0 release adds bounded license inventory, SPDX-style
normalization where available, explicit `UNKNOWN` handling, and policy-backed
license findings. See `docs/license-intelligence.md` for the current behavior.

The implementation remains conservative: it does not infer a license from a
package name, repository URL, or advisory text when the metadata is incomplete.
Any risk category is a configurable policy classification, not legal advice.
