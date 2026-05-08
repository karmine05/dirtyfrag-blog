# investigator's notes — blog source

Source for [investigator.github.io](https://example.github.io/) (replace with your actual GitHub Pages URL once published).

Built with [Hugo](https://gohugo.io/) and the [PaperMod](https://github.com/adityatelange/hugo-PaperMod) theme. Deployed to GitHub Pages via the workflow in `.github/workflows/hugo.yml`.

## Repo layout

```
.
├── content/
│   ├── _index.md                                    # homepage
│   ├── about.md                                     # about page
│   └── posts/
│       └── pre-cve-response-with-fleet/
│           ├── index.md                             # the post
│           └── images/                              # post-bundle images (sanitized)
├── static/
│   └── code/                                        # downloadable artifacts (.sh, .sql, .yml)
├── themes/PaperMod/                                 # submodule — fetched on init
├── .github/workflows/hugo.yml                       # Pages deploy workflow
├── archetypes/default.md
├── hugo.toml                                        # site config
├── .gitignore
├── .gitmodules
├── LICENSE
└── README.md                                        # this file
```

## First-time setup (after cloning)

```bash
git clone --recurse-submodules https://github.com/<you>/<this-repo>.git
cd <this-repo>

# If you forgot --recurse-submodules:
git submodule update --init --recursive
```

## Local development

Install Hugo (extended; on macOS: `brew install hugo`). Then:

```bash
hugo serve
```

Browse to `http://localhost:1313/`. Edits hot-reload.

## Publishing to GitHub Pages

1. Push to GitHub.
2. Repo Settings → Pages → Source: **GitHub Actions**.
3. Edit `hugo.toml` → set `baseURL` to your actual GitHub Pages URL (e.g. `https://<you>.github.io/`).
4. Push again. The workflow in `.github/workflows/hugo.yml` builds and deploys on every push to `main`.

## Adding a new post

```bash
hugo new content posts/my-new-post/index.md
```

That creates a [page bundle](https://gohugo.io/content-management/page-bundles/) so you can drop images alongside the markdown and reference them as `![alt](images/foo.png)`.

## License

All blog content and the artifacts in `static/code/` are MIT-licensed. See [`LICENSE`](LICENSE).
