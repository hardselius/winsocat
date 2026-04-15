# Release Checklist

Steps to cut a new release of winsocat.

## Prepare

Ensure your local `main` is up to date:

```
git checkout main
git pull origin main
```

Review and update dependencies:

```
cargo update
cargo outdated
```

If anything was updated, commit the lockfile:

```
git add Cargo.lock
git commit -m "Update dependencies"
```

## Bump version

Edit `crates/winsocat/Cargo.toml` and set the new version number. Then
update `Cargo.lock` and commit:

```
cargo check --workspace
git add crates/winsocat/Cargo.toml Cargo.lock
git commit -m "Bump version to X.Y.Z"
```

## Verify

Run the full CI checks locally before pushing:

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings -W clippy::all \
  -W clippy::correctness -W clippy::complexity -W clippy::style \
  -W clippy::suspicious -W clippy::perf
cargo test --workspace
cargo build --release --package winsocat
```

## Push and tag

Push the version bump to `main` first, **without** the tag. Wait for CI
to pass before tagging. This avoids a situation where the release
workflow runs against a broken commit.

```
git push origin main
```

Once CI is green, create and push the tag:

```
git tag vX.Y.Z
git push origin vX.Y.Z
```

## Wait for the release workflow

The tag push triggers `.github/workflows/release.yml`, which:

1. Verifies the tag version matches `Cargo.toml`
2. Creates a **draft** GitHub release
3. Builds release binaries for 4 targets:
   - `x86_64-unknown-linux-gnu`
   - `x86_64-apple-darwin`
   - `aarch64-apple-darwin`
   - `x86_64-pc-windows-msvc`
4. Strips binaries (Unix only)
5. Uploads archives with SHA256 checksums

## Publish

Once all build jobs finish, review the draft release on GitHub:

```
gh release view vX.Y.Z
```

Edit the release notes if needed, then publish:

```
gh release edit vX.Y.Z --draft=false
```

## If something goes wrong

If the release build fails, delete the tag and release, fix the issue,
and start over:

```
gh release delete vX.Y.Z --yes
git push origin :refs/tags/vX.Y.Z
git tag -d vX.Y.Z
```

Make fixes, commit, push to `main`, wait for CI, then re-tag.
