# Security Policy

## Reporting a vulnerability

If you discover a security issue in this project, please use GitHub's private vulnerability reporting feature or a private security advisory if the repository owner has enabled it.

Do **not** open a public issue containing:

- Cloudflare API tokens;
- Spamhaus API keys;
- AbuseIPDB API keys;
- private hostnames or internal network details;
- database files containing observed source IPs or request paths;
- full logs that may contain operational information.

If private vulnerability reporting is not available, contact the repository owner through a private channel listed on their GitHub profile or repository metadata.

## Security assumptions

This software is intended to run with:

- a read-only Cloudflare Analytics token scoped to only the required zones;
- reporting API keys for Spamhaus and optional AbuseIPDB stored outside the source tree;
- a dedicated unprivileged service account;
- secrets stored outside the source tree;
- a local SQLite database on a local filesystem;
- automatic submission disabled until shadow-mode output has been reviewed.

The project does not attempt to make attacker-controlled request paths or User-Agent strings trustworthy. They are treated as untrusted input and sanitized before inclusion in logs or submission reasons/comments.
