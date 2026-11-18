# Layout lint

Keeps the tree small enough to read.

- A code or test file has at most 1000 physical lines (`wc -l`).
- A folder holds at most 7 code and test files directly. Subfolders count on
  their own; docs, JSON, TOML, YAML and lock files do not count.
- Code and test files: `.go .rs .ts .tsx .mts .cts .js .mjs .cjs .sh .py`.

When a file or folder is over the limit, split it by topic and move the parts
into subfolders (a Go folder is a package, so a split Go folder becomes
several packages).

```
node tools/layout/check-layout.mjs            # check this repository
node --test tools/layout/check-layout.test.mjs # self-test
```

The file list comes from git (tracked plus untracked and not ignored), so
ignored build output never counts. Exit code 0 is clean, 1 is violations, 2 is
a usage error.
