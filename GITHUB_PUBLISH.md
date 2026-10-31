# Publishing opredir updates to GitHub

The repository is `https://github.com/A-TURBO-99/opredir`.

From the project root, after reviewing the changes:

```bash
git status
git add .
git commit -m "opredir v0.5.1: root CLI workflow and subcommand cleanup"
git tag v0.5.1
git push origin main --tags
```

If your default branch is not `main`, replace `main` with the actual branch name.

After the `v0.5.1` tag is pushed, users can install the latest tagged release with:

```bash
go install github.com/A-TURBO-99/opredir/cmd/opredir@latest
```

The `-o` scan option writes the detailed JSON report. The normal scan output displays confirmed findings by default; use `-hide` to keep finding details in the report without printing them to the terminal. The CLI no longer accepts `--authorized`, `--scope-host`, or `--verbose`; the host scope is still derived internally from the supplied target URLs.


This project release package targets Linux amd64 only. Build and verify releases on Linux; no Windows binary is published.
