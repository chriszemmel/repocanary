set -e
# Build and render one language: sh run.sh de|en (from this folder).
L=$1; S=$(cd "$(dirname "$0")" && pwd)
cd "$S" && python3 build.py "$L" >/dev/null
node "${RENDER_PDF:?set RENDER_PDF to a Playwright HTML-to-PDF script}" "$S/../repocanary-manifest-$L.html" "$S/../repocanary-manifest-$L.pdf" >/dev/null
echo "rendered repocanary-manifest-$L.pdf"
