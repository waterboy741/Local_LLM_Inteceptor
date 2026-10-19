#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle="$repo_root/build/release/llm_interceptor.app"
if [[ $# -ne 0 ]]; then
    echo "This script takes no arguments; packages are written to dist/" >&2
    exit 2
fi
output_dir="$repo_root/dist"
staged_bundle="$output_dir/llm_interceptor.app"
archive="$output_dir/llm_interceptor-macos.zip"

if ! command -v macdeployqt >/dev/null 2>&1; then
    echo "macdeployqt is required to bundle Qt frameworks" >&2
    exit 1
fi

if [[ -L "$output_dir" ]]; then
    echo "Refusing to package through a dist/ symlink" >&2
    exit 1
fi

cmake --preset release -S "$repo_root"
cmake --build --preset release
ctest --preset release --output-on-failure

mkdir -p "$output_dir"
rm -rf "$staged_bundle" "$archive"
ditto "$bundle" "$staged_bundle"
deploy_log="$(mktemp)"
trap 'rm -f "$deploy_log"' EXIT
macdeployqt "$staged_bundle" -no-codesign -no-plugins >"$deploy_log" 2>&1 || {
    cat "$deploy_log" >&2
    exit 1
}
if grep -q '^ERROR:' "$deploy_log"; then
    cat "$deploy_log" >&2
    exit 1
fi
plugin_dir="$(qtpaths --plugin-dir)"
mkdir -p "$staged_bundle/Contents/PlugIns/platforms"
ditto "$plugin_dir/platforms/libqcocoa.dylib" \
    "$staged_bundle/Contents/PlugIns/platforms/libqcocoa.dylib"
install_name_tool -add_rpath '@loader_path/../../Frameworks' \
    "$staged_bundle/Contents/PlugIns/platforms/libqcocoa.dylib"
ditto -c -k --sequesterRsrc --keepParent "$staged_bundle" "$archive"
echo "Created unsigned, local-use package: $archive"
