#!/usr/bin/env bash
# Build the Chrome Web Store upload package.
# Ships only runtime files; zip entries use forward slashes with manifest.json at the root.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(python3 -c "import json;print(json.load(open('manifest.json'))['version'])")
OUT="dist/sentinel-soc-v${VERSION}.zip"

FILES=(
  manifest.json
  background.js content.js inject.js
  popup.html popup.js
  dashboard.html dashboard.js dashboard.css
  warning.html warning.js
  data/brands.json data/popular.json data/threatlist.json data/trackers.json
  rules/trackers.json
  icons/icon16.png icons/icon48.png icons/icon128.png
)

# Sanity checks the store would otherwise reject on
python3 - <<'PY'
import json, sys
m = json.load(open('manifest.json'))
errs = []
if len(m['name']) > 75: errs.append('name > 75 chars')
if len(m.get('description', '')) > 132: errs.append('description > 132 chars (%d)' % len(m['description']))
for f in ['data/brands.json', 'data/popular.json', 'data/threatlist.json', 'data/trackers.json', 'rules/trackers.json']:
    json.load(open(f))
ids = [r['id'] for r in json.load(open('rules/trackers.json'))]
if len(ids) != len(set(ids)): errs.append('duplicate DNR rule ids')
if errs: sys.exit('build: ' + '; '.join(errs))
PY
for f in "${FILES[@]}"; do node --check "$f" 2>/dev/null || [[ "$f" != *.js ]] || { echo "syntax error: $f"; exit 1; }; done

mkdir -p dist
rm -f "$OUT"
zip -q -X "$OUT" "${FILES[@]}"
echo "built $OUT ($(du -h "$OUT" | cut -f1))"
unzip -Z1 "$OUT" | sed "s/^/  /"
