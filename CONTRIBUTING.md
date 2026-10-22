# Contributing

## Commit attribution

Commits are attributed to their author only. AI tool trailers
(`Co-Authored-By: Claude …`, `Claude-Session: …`, `Generated with [Claude Code]`)
are not used in this repository.

Two local settings enforce this. Neither is committed, so set them up in each clone.

### 1. Claude Code: attribution off

`.claude/settings.local.json` (git-ignored):

```json
{
  "includeCoAuthoredBy": false,
  "attribution": { "commit": "", "pr": "" }
}
```

### 2. A `commit-msg` hook that strips the trailers anyway

Git doesn't track `.git/hooks`, so install it by hand:

```sh
cat > .git/hooks/commit-msg <<'EOF'
#!/bin/sh
# Keep commits attributed to their author only: drop AI co-author and
# tool trailers from the message, then any blank lines left at the end.
msg_file="$1"
tmp="$msg_file.tmp.$$"
grep -v -i -E '^[[:space:]]*(Co-Authored-By:[[:space:]]*Claude|Claude-Session:)|Generated with \[Claude Code\]' "$msg_file" > "$tmp" || true
awk '{ lines[NR] = $0 } END { n = NR; while (n > 0 && lines[n] ~ /^[[:space:]]*$/) n--; for (i = 1; i <= n; i++) print lines[i] }' "$tmp" > "$msg_file"
rm -f "$tmp"
EOF
chmod +x .git/hooks/commit-msg
```

Other `Co-Authored-By:` lines (for people) are left alone.

To check a branch: `git log --format='%an <%ae>%n%b' | grep -i claude` should print nothing.
