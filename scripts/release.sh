#!/usr/bin/env bash
# 推送规则：push 代码后，基于最新版本增量创建 tag + GitHub release（不打包应用）
# 用法: scripts/release.sh [major|minor|patch]   默认 patch 递增
set -euo pipefail

REMOTE="${REMOTE:-origin}"
BRANCH="${BRANCH:-main}"
PART="${1:-patch}"

# 1. 获取最新版本（本地与远端取较大者，避免远端有新 tag 时误判）
latest=$(git tag -l 'v*' --sort=-v:refname | head -1)
remote_latest=$(git ls-remote --tags "$REMOTE" 'v*' | sed -E 's#.*refs/tags/(v[0-9.]+)$#\1#' | sort -V | tail -1)
if [[ -n "$remote_latest" ]]; then
    latest=$(printf '%s\n' "$latest" "$remote_latest" | sort -V | tail -1)
fi
latest="${latest:-v0.0.0}"

# 2. 递增版本
IFS=. read -r major minor patch <<< "${latest#v}"
case "$PART" in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
    *) echo "用法: $0 [major|minor|patch]" >&2; exit 1 ;;
esac
new_version="v${major}.${minor}.${patch}"
echo "最新版本: $latest -> 新版本: $new_version"

# 3. 推送代码
git push "$REMOTE" "$BRANCH"

# 4. 增量创建 tag + release（已取消应用打包，仅打 tag 发 release）
git tag -a "$new_version" -m "Release $new_version"
git push "$REMOTE" "$new_version"
gh release create "$new_version" --generate-notes || echo "警告: gh release 创建失败（无 gh 或未登录），tag 已推送"
