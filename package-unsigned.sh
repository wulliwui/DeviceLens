#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output_dir=${1:-"$project_dir/Artifacts"}
mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
stage_dir=$(mktemp -d "${TMPDIR:-/tmp}/deviceinspector-build.XXXXXX")
trap 'rm -rf "$stage_dir"' EXIT

xcodebuild -project "$project_dir/DeviceLens.xcodeproj" -scheme DeviceLens \
  -configuration Release -destination 'generic/platform=iOS' \
  -derivedDataPath "$stage_dir/build" -quiet build CODE_SIGNING_ALLOWED=NO

app="$stage_dir/build/Build/Products/Release-iphoneos/DeviceLens.app"
mkdir "$stage_dir/Payload"
ditto --norsrc "$app" "$stage_dir/Payload/DeviceLens.app"
ditto -c -k --norsrc --keepParent "$stage_dir/Payload" "$stage_dir/DeviceLens-unsigned.ipa"
mv -f "$stage_dir/DeviceLens-unsigned.ipa" "$output_dir/DeviceLens-unsigned.ipa"
shasum -a 256 "$output_dir/DeviceLens-unsigned.ipa"
