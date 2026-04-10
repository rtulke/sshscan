#!/usr/bin/env bash
# update_homebrew.sh — sshscan release helper
# Usage: ./update_homebrew.sh [VERSION]   e.g. ./update_homebrew.sh 3.6.0
#        ./update_homebrew.sh             interactive wizard

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
SSHSCAN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAP_DIR="$HOME/dev/homebrew-sshscan"
FORMULA="$TAP_DIR/Formula/sshscan.rb"
GITHUB_REPO="rtulke/sshscan"
EMPTY_SHA="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# ── Colors (only when attached to a terminal) ─────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  BLUE='\033[0;34m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; DIM=''; NC=''
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
step() { echo -e "\n${BLUE}▸ [${1}]${NC} ${2}"; }
ok()   { echo -e "  ${GREEN}✓${NC} ${1}"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  ${1}"; }
die()  { echo -e "\n${RED}Error:${NC} ${1}" >&2; exit 1; }

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ -f "$SSHSCAN_DIR/sshscan.py" ]] || die "sshscan.py not found in $SSHSCAN_DIR"
[[ -f "$FORMULA" ]]                 || die "Homebrew formula not found at $FORMULA"
command -v git    >/dev/null        || die "git not in PATH"
command -v curl   >/dev/null        || die "curl not in PATH"
command -v python3 >/dev/null       || die "python3 not in PATH"

# ── Detect current version ────────────────────────────────────────────────────
CURRENT_VERSION=$(python3 -c "
import re, sys
m = re.search(r\"__version__\s*=\s*'([^']+)'\", open('$SSHSCAN_DIR/sshscan.py').read())
print(m.group(1)) if m else sys.exit(1)
") || die "Could not detect current version from sshscan.py"

SUGGESTED=$(python3 -c "
v = '${CURRENT_VERSION}'.split('.')
v[-1] = str(int(v[-1]) + 1)
print('.'.join(v))
")

# ── Version input ─────────────────────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
  echo ""
  echo -e "${BOLD}  sshscan — Release Wizard${NC}"
  echo    "  ────────────────────────────────────────────"
  echo -e "  Current version : ${YELLOW}${CURRENT_VERSION}${NC}"
  echo -e "  ${DIM}Leave blank to use suggested: ${SUGGESTED}${NC}"
  echo ""
  read -r -p "  New version: " NEW_VERSION
  [[ -z "$NEW_VERSION" ]] && NEW_VERSION="$SUGGESTED"
  echo ""
else
  NEW_VERSION="${1}"
fi

# ── Validate ──────────────────────────────────────────────────────────────────
[[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || die "Version must be in X.Y.Z format (got: '$NEW_VERSION')"
[[ "$NEW_VERSION" != "$CURRENT_VERSION" ]] \
  || die "New version is identical to current ($CURRENT_VERSION)"

# ── Confirm ───────────────────────────────────────────────────────────────────
echo -e "  ${BOLD}${YELLOW}${CURRENT_VERSION}${NC}  →  ${BOLD}${GREEN}${NEW_VERSION}${NC}"
echo ""
echo    "  What will happen:"
echo    "    1  Update sshscan.py, README.md, CHANGELOG.md"
echo    "    2  git commit  +  tag v${NEW_VERSION}  +  push  [sshscan]"
echo    "    3  Download release tarball, compute SHA256"
echo    "    4  Update Homebrew formula (url + sha256)"
echo    "    5  git commit  +  push  [homebrew-sshscan]"
echo ""
read -r -p "  Proceed? [y/N] " CONFIRM
echo ""
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { echo "  Aborted."; exit 0; }

# ── Step 1: Update source files ───────────────────────────────────────────────
step "1/5" "Updating source files"

# sshscan.py
sed -i.bak "s/__version__ = '${CURRENT_VERSION}'/__version__ = '${NEW_VERSION}'/" \
  "$SSHSCAN_DIR/sshscan.py"
rm -f "$SSHSCAN_DIR/sshscan.py.bak"
ok "sshscan.py  (__version__ = '${NEW_VERSION}')"

# README.md
sed -i.bak "s/\*\*Version:\*\* ${CURRENT_VERSION}/**Version:** ${NEW_VERSION}/" \
  "$SSHSCAN_DIR/README.md"
rm -f "$SSHSCAN_DIR/README.md.bak"
ok "README.md"

# CHANGELOG.md — insert placeholder section above current release entry
python3 - <<PYEOF
with open('${SSHSCAN_DIR}/CHANGELOG.md', 'r') as f:
    content = f.read()

old_marker  = '## [${CURRENT_VERSION}] \u2014 Current'
new_marker  = '## [${CURRENT_VERSION}]'
new_section = (
    '## [${NEW_VERSION}] \u2014 Current\n\n'
    '### New Features\n\n'
    '- <!-- describe changes here -->\n\n'
    '---\n\n'
)

if old_marker in content:
    content = content.replace(old_marker, new_section + new_marker, 1)
else:
    # fallback: no "— Current" suffix on old version
    fallback = '## [${CURRENT_VERSION}]'
    content = content.replace(fallback, new_section + fallback, 1)

with open('${SSHSCAN_DIR}/CHANGELOG.md', 'w') as f:
    f.write(content)
PYEOF
ok "CHANGELOG.md  (placeholder section added for ${NEW_VERSION})"
warn "Remember to fill in the CHANGELOG entry before announcing the release."

# ── Step 2: Commit, tag, push ─────────────────────────────────────────────────
step "2/5" "Committing, tagging, pushing sshscan"

cd "$SSHSCAN_DIR"
git add sshscan.py README.md CHANGELOG.md
git commit -m "Bump version to ${NEW_VERSION}"
git tag "v${NEW_VERSION}"
git push origin main
git push origin "v${NEW_VERSION}"
ok "Pushed  main  +  tag v${NEW_VERSION}  →  github.com/${GITHUB_REPO}"

# ── Step 3: Download tarball and compute SHA256 ───────────────────────────────
step "3/5" "Fetching release tarball SHA256"

TARBALL_URL="https://github.com/${GITHUB_REPO}/archive/refs/tags/v${NEW_VERSION}.tar.gz"
SHA256=""
MAX_ATTEMPTS=10

for ((i=1; i<=MAX_ATTEMPTS; i++)); do
  echo -e "  ${DIM}Attempt ${i}/${MAX_ATTEMPTS} — waiting for GitHub to publish tarball...${NC}"
  sleep 6
  SHA256=$(curl -sL "$TARBALL_URL" | shasum -a 256 | awk '{print $1}')
  if [[ -n "$SHA256" && "$SHA256" != "$EMPTY_SHA" ]]; then
    ok "SHA256: ${SHA256}"
    break
  fi
  SHA256=""
done

[[ -n "$SHA256" ]] || die \
  "Could not download release tarball after ${MAX_ATTEMPTS} attempts.
  URL: ${TARBALL_URL}
  Compute manually:  curl -sL \"${TARBALL_URL}\" | shasum -a 256
  Then update:       ${FORMULA}"

# ── Step 4: Update Homebrew formula ──────────────────────────────────────────
step "4/5" "Updating Homebrew formula"

python3 - <<PYEOF
import re

with open('${FORMULA}', 'r') as f:
    content = f.read()

# Update the main formula URL (only the github/sshscan line, not pyyaml resource)
content = re.sub(
    r'(  url "https://github\.com/${GITHUB_REPO}/archive/refs/tags/v)[^"]+',
    r'\g<1>${NEW_VERSION}.tar.gz',
    content
)

# Update the formula-level sha256 only (first sha256, before any resource block)
parts = content.split('  resource ', 1)
header = re.sub(
    r'(  sha256 ")[a-f0-9]+(")',
    r'\g<1>${SHA256}\g<2>',
    parts[0],
    count=1
)
content = header + ('  resource ' + parts[1] if len(parts) > 1 else '')

# Update version string in the test block
content = content.replace('"${CURRENT_VERSION}"', '"${NEW_VERSION}"')

with open('${FORMULA}', 'w') as f:
    f.write(content)
PYEOF
ok "Formula: url → v${NEW_VERSION}, sha256 → ${SHA256:0:16}..."

# ── Step 5: Commit and push tap ───────────────────────────────────────────────
step "5/5" "Committing and pushing homebrew-sshscan"

cd "$TAP_DIR"
git add Formula/sshscan.rb
git commit -m "Update sshscan formula to v${NEW_VERSION}"
git push origin main
ok "Pushed  →  github.com/rtulke/homebrew-sshscan"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  ✓  Release v${NEW_VERSION} complete${NC}"
echo ""
echo    "  GitHub release : https://github.com/${GITHUB_REPO}/releases/tag/v${NEW_VERSION}"
echo    "  Homebrew tap   : brew upgrade sshscan"
echo ""
echo -e "  ${YELLOW}Next:${NC} fill in CHANGELOG.md for v${NEW_VERSION} and commit."
echo ""
