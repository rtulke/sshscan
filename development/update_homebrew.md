# update_homebrew.sh — Release Helper

For sshscan core-developer only!

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


**1. Clone repositories


Make sure you're in the "sshscan" directory! For example, the "sshscan" and "hombrew_scan" repositories are located in your "dev" directory; if they aren't, you should create them there.


 - https://github.com/rtulke/homebrew-sshscan
 - https://github.com/rtulke/sshscan

```bash
cd dev/
git clone https://github.com/rtulke/sshscan.git
git clone git@github.com:rtulke/homebrew-sshscan.git
```


**2. Commit all pending changes first**


The script only stages `sshscan.py`, `README.md`, and `CHANGELOG.md`.
Everything else (feature work, reorganisation, config changes) must be committed before running it:

Change to the sshscan directory

```bash
cd dev/sshscan
```

You've made some changes to the code and want to commit a new version.

```
git add .
git commit -m "Your commit message"
git push origin main
```

**3. Run the script**


```bash
./development/update_homebrew.sh 3.6.1
# or without an argument to use the interactive wizard:
./development/update_homebrew.sh
```

The script handles everything from here: version bump, commit, tag, push, SHA256,
Homebrew formula update, and the tap commit/push.

**4. Fill in the CHANGELOG (prompted by the script)**

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

## Manual recovery (if the script fails mid-run)

If the script aborted after bumping the version in the source files but before
committing, finish the release by hand. Replace `X.Y.Z` with the target version.

**1. Commit, tag, and push the sshscan repo**

```bash
cd ~/dev/sshscan

git add sshscan.py README.md CHANGELOG.md
git commit -m "Bump version to X.Y.Z"
git tag vX.Y.Z
git push origin main
git push origin vX.Y.Z
```

**2. Fetch the tarball SHA256**

Wait a few seconds for GitHub to publish the tag, then:

```bash
curl -sL https://github.com/rtulke/sshscan/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256
```

**3. Update the Homebrew formula**

Edit `~/dev/homebrew-sshscan/Formula/sshscan.rb` — update the `url` (version in
the tarball path) and the formula-level `sha256` with the hash from step 2.

**4. Commit and push the tap**

```bash
cd ~/dev/homebrew-sshscan

git add Formula/sshscan.rb
git commit -m "Update sshscan formula to vX.Y.Z"
git push origin main
```

## Requirements

The following tools must be available in `PATH`: `git`, `curl`, `python3`

The Homebrew tap repo is expected at `~/dev/homebrew-sshscan/`.
