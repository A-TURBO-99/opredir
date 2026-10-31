# Publish opredir to GitHub

The source tree is prepared for this module path:

`github.com/A-TURBO-99/opredir`

The repository must exist and be public before other users can run `git clone`
from GitHub or install it with `go install ...@latest`.

## 1. Create the GitHub repository

Create a **public** repository named `opredir` under the `A-TURBO-99` account.
Do not initialize it with a README, license, or `.gitignore` because those files
are already present in this source tree.

## 2. Push this project

Run these commands from the project root:

```bash
git init -b main
git add .
git commit -m "Initial release: opredir v0.4.2"
git remote add origin https://github.com/A-TURBO-99/opredir.git
git push -u origin main
git tag v0.4.2
git push origin v0.4.2
```

## 3. Install from GitHub

After the public repository and `v0.4.2` tag are available:

```bash
go install github.com/A-TURBO-99/opredir/cmd/opredir@latest
```

The binary is written to `$(go env GOPATH)/bin` unless `GOBIN` is set.
