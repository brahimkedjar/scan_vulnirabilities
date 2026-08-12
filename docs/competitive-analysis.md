# Capability comparison with Red Hat Dependency Analytics

This comparison is a scope map, not a performance benchmark or a claim of
overall superiority. Product capabilities and documentation change; the links
below were reviewed on 2026-08-12.

Red Hat documentation describes Red Hat Dependency Analytics (RHDA) as an IDE
experience backed by the Exhort/Red Hat Trusted Profile Analyzer service. The
older RHDA quick start documents OSV and NVD vulnerability sources and support
for Maven, Node.js, Python, and Go projects. Current Red Hat Trusted Profile
Analyzer documentation describes a hosted software-composition-analysis and
SBOM platform, and its IDE quick start documents additional supported package
and project contexts.

Sources:

- [Red Hat Trusted Profile Analyzer 2.0 overview](https://docs.redhat.com/en/documentation/red_hat_trusted_profile_analyzer/2.0/html/administration_guide/con_overview-of-red-hat-trusted-profile-analyzer_admin)
- [Red Hat Dependency Analytics 1.0 quick start](https://docs.redhat.com/en/documentation/red_hat_trusted_profile_analyzer/1/html-single/quick_start_guide/index)
- [Red Hat Trusted Profile Analyzer 2.0 quick start](https://docs.redhat.com/en/documentation/red_hat_trusted_profile_analyzer/2/html-single/quick_start_guide/index)

## Comparison

| Dimension | Dependency Vulnerability Auditor, current slice | RHDA / Red Hat Trusted Profile Analyzer, as documented |
|---|---|---|
| Primary shape | VS Code workspace extension with local static parsers | IDE analysis backed by Red Hat's hosted analysis platform; RHTPA also provides centralized application/SBOM workflows |
| Dependency discovery | 13 bounded static adapters mapped to 7 OSV ecosystems; never runs package managers or build tools | Red Hat quick starts document supported manifest/package-manager contexts and service-backed analysis |
| Vulnerability intelligence | Exact-version OSV lookup plus local CISA KEV enrichment; provider-neutral evidence model currently receives OSV observations only | Older RHDA documentation explicitly describes OSV and NVD; current RHTPA documentation describes its Trusted Content service |
| Exploitation evidence | Exact CVE matching against a fresh CISA KEV catalog with stale/unavailable states kept `UNKNOWN` | Not evaluated here; the cited documentation should be used for current source details |
| Risk explanation | Deterministic evidence-backed lower and upper bounds from severity, CVSS, KEV, and reachability; current reachability is always unknown | Red Hat's service provides its own analysis and recommendation model; the scoring methods are not treated as equivalent |
| Policy gate | Local bounded evaluator for severity/CVSS counts and thresholds, known-exploitation absence, ecosystem/package allow/block rules, and expiring advisory ignores | RHTPA is positioned for organization-level software-composition workflows; this document does not assert rule-by-rule equivalence |
| SBOM and reports | CycloneDX JSON 1.6 generation and SARIF 2.1.0 generation from the stored scan; no import, lifecycle store, or server | RHTPA provides hosted SBOM/application analysis and management workflows |
| Containers | No container or Dockerfile analysis | Current Red Hat quick-start documentation includes supported container/Dockerfile analysis contexts |
| Reachability | No source/call-graph reachability engine; the factor is explicitly `UNKNOWN` | Not compared without a like-for-like documented algorithm |
| Operation and privacy | Workspace metadata is parsed locally; exact package coordinates go to OSV, while the KEV catalog download carries no project data | Analysis is service-backed according to Red Hat documentation; deployment and data-governance details depend on the selected Red Hat offering |
| Automation | No headless scan CLI, CI task, PR annotation, or centralized dashboard | RHTPA provides a broader hosted platform and integration surface |

## Where this extension is deliberately different

The extension emphasizes a small, inspectable VS Code trust boundary:

- local, bounded, static parsing across a broad set of package metadata;
- no package-manager, build-tool, shell, task, or project-code execution;
- exact evidence provenance, conflict retention, and explicit unknown states;
- fail-closed coverage and gate semantics; and
- local generation of deterministic CycloneDX JSON and SARIF output.

These are useful design choices, not proof that the extension is universally
safer or more capable than RHDA/RHTPA. In particular, static parsing trades
execution risk for incomplete coverage when a package manager or build system
is needed to resolve a dynamic graph.

## Where Red Hat's documented platform is broader

RHTPA is the stronger fit when an organization needs a hosted application and
SBOM lifecycle, centralized analysis, enterprise service integration, or the
container and project contexts documented by Red Hat. The current extension
does not attempt to reproduce that server-side platform.

The defensible current differentiator is therefore transparent local static
analysis and evidence-preserving fail-closed behavior across the extension's
supported metadata formats—not a blanket claim of feature or detection
superiority.
