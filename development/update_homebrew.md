# update_homebrew.sh — Release Helper

Updates the version in source code, README, CHANGELOG, commits and tags the
sshscan repo, computes the release tarball SHA256, and updates the Homebrew formula.

## One-time setup

```bash
chmod +x development/update_homebrew.sh
```

## Usage

```bash
# With explicit version:
./development/update_homebrew.sh 3.6.0

# Without argument — interactive wizard:
./development/update_homebrew.sh
```

The wizard automatically suggests the next patch version (e.g. `3.5.0` → `3.5.1`)
and shows a confirmation prompt before doing anything.

## What happens

| Step | Action |
|---|---|
| 1 | Update `sshscan.py`, `README.md`, `CHANGELOG.md` to the new version |
| 2 | `git commit` + `tag vX.Y.Z` + `git push` in the sshscan repo |
| 3 | Download release tarball from GitHub, compute SHA256 (up to 10 attempts) |
| 4 | Update `url`, `sha256`, and test version string in the Homebrew formula |
| 5 | `git commit` + `git push` in the homebrew-sshscan repo |

## After the release

- Fill in the `CHANGELOG.md` entry for the new version and commit
- Users can upgrade with `brew upgrade sshscan`

## Requirements

The following tools must be available in `PATH`: `git`, `curl`, `python3`

The Homebrew tap repo is expected at `~/dev/homebrew-sshscan/`.
