#!/bin/sh
# Build the Sudaeon Debian package from a plain source checkout.
#
# This is meant to work after "Code -> Download ZIP" from GitHub: unpack the
# archive, run this script, install the .deb it produces.
#
#   sudo apt install build-essential dpkg-dev libpam0g-dev python3
#   ./tools/build-deb.sh
#   sudo apt install ./dist/sudaeon_*.deb
#   sudaeon setup
#
# The script is a thin wrapper around dpkg-buildpackage; the packaging itself
# lives in debian/.  It never needs root and never touches the system, except
# when --install is given.
set -eu

usage() {
    cat <<'USAGE'
usage: tools/build-deb.sh [--install] [--no-check] [--stub-pam] [--dist DIR]

  --install     install the package with apt after a successful build (sudo)
  --no-check    skip the build dependency check
  --stub-pam    build against tests/c/stubs instead of the real PAM headers
                (development only - the package must NOT be installed)
  --dist DIR    where the .deb is placed (default: dist/)
  -h, --help    this text
USAGE
}

install_after=0
check_deps=1
stub_pam=0
dist="dist"

while [ $# -gt 0 ]; do
    case "$1" in
        --install) install_after=1 ;;
        --no-check) check_deps=0 ;;
        --stub-pam) stub_pam=1; check_deps=0 ;;
        --dist) shift; dist="${1:?--dist needs a directory}" ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [ "$stub_pam" = 1 ] && [ "$install_after" = 1 ]; then
    echo "--stub-pam and --install do not go together: the stub module must not" >&2
    echo "be installed on a real computer." >&2
    exit 2
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

missing=""
for tool in make gcc dpkg-buildpackage dpkg-architecture dpkg-deb python3; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
    echo "missing tools:$missing" >&2
    echo >&2
    echo "install them with:" >&2
    echo "  sudo apt install build-essential dpkg-dev libpam0g-dev python3" >&2
    exit 1
fi

if [ "$stub_pam" = 1 ]; then
    echo "!! building with the stub PAM headers from tests/c/stubs" >&2
    echo "!! the result is for development only and must not be installed" >&2
    export SUDAEON_STUB_PAM=1
elif [ ! -f /usr/include/security/pam_appl.h ]; then
    echo "the PAM development headers are missing." >&2
    echo "  sudo apt install libpam0g-dev" >&2
    exit 1
fi

if [ "$check_deps" = 1 ] && command -v dpkg-checkbuilddeps >/dev/null 2>&1; then
    if ! dpkg-checkbuilddeps 2>/tmp/sudaeon-builddeps.$$; then
        echo "the build dependencies are not installed:" >&2
        sed 's/^/  /' /tmp/sudaeon-builddeps.$$ >&2
        echo >&2
        echo "install them with:" >&2
        echo "  sudo apt install build-essential dpkg-dev libpam0g-dev python3" >&2
        rm -f /tmp/sudaeon-builddeps.$$
        exit 1
    fi
    rm -f /tmp/sudaeon-builddeps.$$
fi

chmod +x debian/rules

echo "==> building sudaeon"
# -us -uc: no signing; -b: binary package only; fakeroot is not needed because
# debian/control declares "Rules-Requires-Root: no".  A stub build also passes
# -d, because libpam0g-dev is exactly what is missing in that case.
extra=""
[ "$stub_pam" = 1 ] && extra="-d"
dpkg-buildpackage -us -uc -b $extra

version=$(dpkg-parsechangelog --file debian/changelog -SVersion)
arch=$(dpkg-architecture -qDEB_HOST_ARCH)
built="../sudaeon_${version}_${arch}.deb"

if [ ! -f "$built" ]; then
    echo "the package was not produced where it was expected: $built" >&2
    exit 1
fi

# A stub build is marked, so it can never be mistaken for a real package.
label="$arch"
[ "$stub_pam" = 1 ] && label="${arch}+stub"
mkdir -p "$dist"
cp -f "$built" "$dist/sudaeon_${version}_${label}.deb"
rm -f "$built" "../sudaeon_${version}_${arch}.buildinfo" \
      "../sudaeon_${version}_${arch}.changes"
final="$root/$dist/sudaeon_${version}_${label}.deb"

echo
echo "==> built $final"
dpkg-deb --info "$final" | sed -n '1,12p'

if [ "$install_after" = 1 ]; then
    echo
    echo "==> installing (sudo apt install)"
    sudo apt install -y "$final"
    echo
    echo "Sudaeon is installed.  Run 'sudaeon setup' (or open Sudaeon from the"
    echo "application menu) to choose the master password - until then nothing"
    echo "is enforced."
else
    cat <<EOF

install it with:
  sudo apt install "$final"

then choose the master password:
  sudaeon setup
EOF
fi
