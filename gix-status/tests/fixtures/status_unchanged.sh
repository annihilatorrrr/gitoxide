#!/usr/bin/env bash
set -eu -o pipefail

git init -q

touch empty
echo -n "content" > executable
chmod +x executable

mkdir dir
echo -n "other content" > dir/content
mkdir dir/sub-dir
(cd dir/sub-dir && ln -sf ../content symlink)

git add -A
git update-index --chmod=+x executable  # For Windows.
git commit -m "Commit"

touch ./empty ./executable ./dir/content ./dir/sub-dir/symlink

git reset # ensure index timestamp is large enough to not mark everything racy
