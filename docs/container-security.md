# Container security

Container analysis is static and does not require a Docker daemon.

Supported inputs include:
- OCI image layouts
- Docker archive/tar files
- SBOM files associated with an image
- image metadata

The analyzer does not execute containers, invoke Docker automatically, or call shell commands. It reports `IMAGE UNKNOWN` whenever the available evidence is insufficient.