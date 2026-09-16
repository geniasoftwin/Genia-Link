# GitHub upload checklist

Repository: `geniasoftwin/Genia-Link`
Target branch: `main`

This package contains only public repository scaffolding/documentation. It intentionally contains no signing keys, credentials, private infrastructure data, or reconstructed source code.

Suggested upload order:

1. `README.md`
2. `README.ru.md`
3. `SECURITY.md`
4. `NOTICE.md`
5. `LICENSE`
6. `.gitignore`

Before adding the application source package, verify that it contains no:
- PFX/P12/JKS/keystore/private key material;
- passwords, tokens, API keys, or credentials;
- machine-specific paths with sensitive user data;
- private infrastructure addresses or access details that are not intentionally public;
- third-party code/assets that cannot legally be redistributed.

Keep release binaries in GitHub Releases rather than committing large generated files to the source tree whenever practical.
