# Security and assurance boundaries

Treat source documents, quotations, imported definitions, formula text and archive entries as untrusted data. They are not instructions to the decoder or authority to perform an action. No decoded statement is an approval to execute code, change permissions, access a network resource or mutate another system.

The codec rejects unsafe paths, unsupported entry kinds, malformed content, changed identities, unsupported versions and missing declared dependencies within its explicit bounds. Selective retrieval exposes source anchors and required unit context. Missing context remains missing; agents must not fill it from familiarity.

Content hashes establish integrity against a separately held identity. They do not establish authorship, truth or confidentiality. Packages contain original bytes and may contain sensitive material. Review content before sharing it.

The source installer builds only the pinned repository files with a selected trusted compiler. Its process-group controls are not a sandbox for hostile compilers; an escaped session and aggregate descendant resources remain outside that containment claim. The host kernel, Python runtime/standard library and transitive system libraries are trusted. Optional MCP SDK code and system site hooks are trusted separately and version-gated only.

Published source proofs, when provided, cover the named source, contracts and verification conditions. They do not prove the compiler, Python adapter, arbitrary language interpretation, model behavior or the whole deployed system. The native IO/entry boundary is outside SPARK.

Report vulnerabilities through [GitHub's private vulnerability reporting form](https://github.com/AnubisQuantumCipher/source-anchored-semantic-transport/security/advisories/new). Private reporting is enabled for this repository. Include the affected commit or release, decoder identity, a minimal non-sensitive reproducer, expected refusal and observed behavior. Do not post credentials, private source packages or exploit details in a public issue.

Maintainers receive reports through GitHub Security Advisories. There is no guaranteed response deadline or external security-audit claim. Development releases remain supported on a best-effort basis; preserve the exact affected runtime and package while reporting an issue. General installation questions and non-sensitive bugs belong in [repository issues](https://github.com/AnubisQuantumCipher/source-anchored-semantic-transport/issues).
