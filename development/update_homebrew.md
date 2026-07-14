# update_homebrew.sh — Release Helper

For sshscan core-developer only!

Bumps the version in the source, README and CHANGELOG, commits and tags the sshscan
repo, computes the release tarball SHA256 and updates the Homebrew formula.

Pushing the tag additionally triggers `.github/workflows/release.yml`, which builds
the binaries and the `.deb`/`.rpm` packages and attaches them to the GitHub release.
That part runs on GitHub, not on your machine — the script does not wait for it.

## One-time setup

Both repos must sit next to each other under `~/dev/`:

```bash
cd ~/dev
git clone https://github.com/rtulke/sshscan.git
git clone git@github.com:rtulke/homebrew-sshscan.git
chmod +x sshscan/development/update_homebrew.sh
```

## Before you release

**1. Commit everything you want in the release.**
The script only stages `sshscan.py`, `README.md` and `CHANGELOG.md`. Anything else
in the working tree is left behind and silently misses the release:

```bash
cd ~/dev/sshscan
git add . && git commit -m "..." && git push origin main
```

This matters most for `.github/workflows/release.yml`: **GitHub reads the workflow
from the tagged commit.** If a workflow change is not pushed before you tag, the tag
runs the old version — or, if the file did not exist yet, nothing at all.

**2. Make sure the test suite passes.**

```bash
python3 -m unittest discover -s tests
```

**3. Have the CHANGELOG text ready.**
The script inserts a placeholder and opens `$EDITOR` mid-run. Do not pre-write the
section into `CHANGELOG.md` — you would end up with it twice.

## Run it

```bash
./development/update_homebrew.sh 3.7.4     # explicit version
./development/update_homebrew.sh           # interactive wizard, suggests the next patch
```

## What happens

| Step | Action | Where |
|---|---|---|
| 1 | Bump the version in `sshscan.py`, `README.md` (version line **and** the package download URLs, which carry the version in the filename) and insert a CHANGELOG placeholder, then open `$EDITOR` | local |
| 2 | `git commit` + `tag vX.Y.Z` + `git push` | sshscan repo |
| 3 | Download the release tarball, compute its SHA256 (up to 10 attempts, GitHub needs a few seconds) | local |
| 4 | Update `url`, `sha256` and the test version string in the formula | tap repo |
| 5 | `git commit` + `git push` | tap repo |
| 6 | *(triggered by the tag, runs on GitHub)* build binaries, build `.deb`/`.rpm`, install and run them in Debian 12/13, Rocky 9 and Fedora containers, attach everything to the release | GitHub Actions |

## After the release

```bash
gh run list --workflow=release.yml --limit 1   # step 6 -- takes a few minutes
gh release view vX.Y.Z                         # should list 16 assets
brew update && brew upgrade sshscan
```

## Two rules that will bite you

**Never rewrite or move a published tag.** The tarball SHA256 in the Homebrew formula
is derived from it. Moving the tag changes the tarball, the recorded hash no longer
matches, and `brew install` fails with "SHA256 mismatch" for everyone until you
re-point the formula. This also makes a `git rebase` over an already-tagged commit
expensive: it invalidates every tag above it.

**The release script does no `git pull`.** If `origin/main` moved on since your last
fetch, `git push origin main` fails *after* the commit and *before* the tag, leaving
the release half-done. Recover with the manual steps below.

## Manual recovery (if the script fails mid-run)

Replace `X.Y.Z` with the target version.

**1. Commit, tag and push the sshscan repo**

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
curl -fsL https://github.com/rtulke/sshscan/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256
```

The `-f` is not optional. Without it, curl prints GitHub's 404 page on an HTTP error
instead of failing, `shasum` cheerfully hashes that HTML, and the hash of an error
page ends up in the formula. If the command prints nothing, the tarball is not ready
yet — wait and retry rather than hashing whatever comes back.

**3. Update the Homebrew formula**

Edit `~/dev/homebrew-sshscan/Formula/sshscan.rb`: the `url` (version in the tarball
path) and the **formula-level** `sha256` — not the one inside the `resource "pyyaml"`
block.

**4. Commit and push the tap**

```bash
cd ~/dev/homebrew-sshscan
git add Formula/sshscan.rb
git commit -m "Update sshscan formula to vX.Y.Z"
git push origin main
```

## Requirements

`git`, `curl`, `python3`, `shasum` in `PATH`. The tap repo is expected at
`~/dev/homebrew-sshscan/`. The binary/package build needs nothing locally — it runs
on GitHub's runners.
