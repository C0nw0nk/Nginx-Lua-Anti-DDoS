#!/bin/bash

set -euo pipefail

CHANGELOG_FILE="CHANGELOG"
SPEC_FILE="rpm/anti_ddos_challenge.spec"
DEB_CHANGELOG="debian/changelog"
PACKAGE_NAME="nginx-lua-anti-ddos-challenge"
MAINTAINER_NAME="C0nw0nk"
MAINTAINER_EMAIL="C0nw0nk@github"

# 1️⃣ Get script version from lua file
SCRIPT_VERSION=$(sed -n 's/^Script Version: //p' lua/anti_ddos_challenge.lua)
[ -z "$SCRIPT_VERSION" ] && echo "ERROR: Cannot find Script Version in Lua file" && exit 1

# 2️⃣ Extract changelog block for this version
CHANGE_BLOCK=$(awk -v ver="$SCRIPT_VERSION" '
  BEGIN {found=0}
  /^Version: / {
    if ($2 == ver) {found=1; next}
    else if (found) {exit}
  }
  found {print}
' "$CHANGELOG_FILE")

[ -z "$CHANGE_BLOCK" ] && echo "ERROR: Version $SCRIPT_VERSION not found in $CHANGELOG_FILE" && exit 1

# 3️⃣ Extract date and entries separately
CHANGE_DATE=$(echo "$CHANGE_BLOCK" | awk '/^Date:/ {print $2}')
CHANGE_ENTRIES=$(echo "$CHANGE_BLOCK" | awk '!/^Date:/ {print}')

# 4️⃣ Prepare RPM changelog entry
DATE_RPM=$(date -d "$CHANGE_DATE" +"%a %b %d %Y")
{
  echo "* $DATE_RPM $MAINTAINER_NAME <$MAINTAINER_EMAIL> - $SCRIPT_VERSION-1"
  # Only add dash if missing
  echo "$CHANGE_ENTRIES" | sed '/^-/!s/^/- /'
} > changelog.newentry

# 5️⃣ Inject into SPEC while keeping old entries
awk '
  BEGIN {done=0}
  /^%changelog/ {
    print "%changelog"
    system("cat changelog.newentry")
    done=1
    next
  }
  done==1 { print; next }  # print existing old changelog lines
  { print }
' "$SPEC_FILE" > "$SPEC_FILE.new"

mv "$SPEC_FILE.new" "$SPEC_FILE"

# 6️⃣ Generate Debian changelog (append old entries below new one)
DATE_DEB=$(date -d "$CHANGE_DATE" +"%a, %d %b %Y %H:%M:%S %z")
{
  echo "$PACKAGE_NAME ($SCRIPT_VERSION-1) stable; urgency=medium"
  echo "$CHANGE_ENTRIES" | sed 's/^/  /'
  echo
  echo " -- $MAINTAINER_NAME <$MAINTAINER_EMAIL>  $DATE_DEB"
  echo
  # If old deb changelog exists, append it
  if [ -f "$DEB_CHANGELOG" ]; then
    tail -n +1 "$DEB_CHANGELOG"
  fi
} > "$DEB_CHANGELOG.tmp"

mv "$DEB_CHANGELOG.tmp" "$DEB_CHANGELOG"

echo "✅ Changelog for version $SCRIPT_VERSION added to:"
echo "   - $SPEC_FILE (%changelog) (old entries preserved)"
echo "   - $DEB_CHANGELOG (old entries preserved)"