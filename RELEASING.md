# Releasing

Versions are calendar versions, `YYYY.MMDD.N`: the release date, then a build number that starts at 1
(the first release is `2026.1116.1`). Every manifest carries the version, and the git tag is `v` plus
the version. A version, once published, can never be published again with different content.

To release:

1. Set the new version in `package.json`, `package-lock.json` and `src/transport.ts` (`LIBRARY_VERSION`) and add it to the changelog or README where the old one appears.
2. Merge to `main` with CI green.
3. Tag the merge commit and push the tag: `git tag -a v<version> -m "<version>" && git push origin v<version>`.
4. The tag starts `.github/workflows/release.yml`, which waits for a reviewer to approve the `npm` environment, checks the tag against `package.json`, runs the tests and runs `npm publish --provenance` by npm trusted publishing (OIDC).

npm trusted publisher: organisation or user `abiz-org`, repository `abiz-js`, workflow `release.yml`, environment `npm`.

The first version cannot go through OIDC, because npm only accepts a trusted publisher for a package that already exists. It is published once by hand from a clean checkout of the tag (`npm ci --ignore-scripts && npm test && npm publish --access public`), signed in with `npm login --auth-type=web`. Then add the trusted publisher above and set the package to require 2FA and disallow tokens.

Every publishing environment requires a reviewer's approval, and tags matching `v*` are protected.
