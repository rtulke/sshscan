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

## Release workflow

The script expects a clean working tree. Follow these three steps:

**1. Commit all pending changes first**

The script only stages `sshscan.py`, `README.md`, and `CHANGELOG.md`.
Everything else (feature work, reorganisation, config changes) must be committed before running it:

```bash
git add .
git commit -m "Your commit message"
git push origin main
```

**2. Run the script**

```bash
./development/update_homebrew.sh 3.6.1
# or without an argument to use the interactive wizard:
./development/update_homebrew.sh
```

The script handles everything from here: version bump, commit, tag, push, SHA256,
Homebrew formula update, and the tap commit/push.

**3. Fill in the CHANGELOG (prompted by the script)**

After inserting the placeholder, the script opens `$EDITOR` (falls back to `vi`)
so you can fill in the new version section immediately. Save and quit — the script
commits the finished CHANGELOG together with the version bump and continues.

---

## What happens

| Step | Action |
|---|---|
| 1 | Update `sshscan.py`, `README.md`, `CHANGELOG.md` to the new version |
| 2 | `git commit` + `tag vX.Y.Z` + `git push` in the sshscan repo |
| 3 | Download release tarball from GitHub, compute SHA256 (up to 10 attempts) |
| 4 | Update `url`, `sha256`, and test version string in the Homebrew formula |
| 5 | `git commit` + `git push` in the homebrew-sshscan repo |

## After the release

- Users can upgrade with `brew upgrade sshscan`

## Requirements

The following tools must be available in `PATH`: `git`, `curl`, `python3`

The Homebrew tap repo is expected at `~/dev/homebrew-sshscan/`.
