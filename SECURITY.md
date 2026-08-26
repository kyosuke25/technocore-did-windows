# Security Policy

## Secret handling

Never include any of the following in a bug report, issue, pull request, log, or screenshot:

- `.technocore/identity.dpapi`
- an exported Ed25519 private key
- wallet seeds or private keys
- API keys, passwords, or authentication tokens

The DPAPI ciphertext is still sensitive. It is bound to the current Windows user, but it should not be published or treated as harmless.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for vulnerabilities in this repository. Do not open a public issue containing an exploit or secret material.
