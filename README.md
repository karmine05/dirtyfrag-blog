# karmine's notes

Source for <https://karmine05.github.io/dirtyfrag-blog/>: security operations, Fleet/osquery detection engineering and agentic AI.

Built with [Hugo](https://gohugo.io/) Extended (0.168.0 or newer) and the [OINK](https://github.com/pgsty/oink) theme, pulled in as a Hugo Module (pinned in `go.mod`). Deployed to GitHub Pages by `.github/workflows/hugo.yml` on every push to `main`.

## Layout

```
.
├── hugo.yaml                  # the only site config
├── go.mod / go.sum            # pins the OINK theme version
├── data/home/en.yaml          # home page sections (hero, metrics, recent posts)
├── content/
│   ├── _index.md              # home
│   ├── about/                 # about page
│   └── posts/<slug>/          # one page bundle per post: index.md, cover.svg, images/
├── assets/covers/             # copies of post covers for the home page cards
├── static/code/               # downloadable queries, scripts, policies
└── scripts/gen_covers.py      # regenerates every post's cover.svg
```

## Local development

Needs Go 1.27+ and Hugo **Extended** (the standard build cannot compile the theme's Sass).

```bash
hugo server
```

Open <http://localhost:1313/dirtyfrag-blog/>. Production check:

```bash
hugo --gc --minify --environment production --printPathWarnings
```

## Writing a post

```bash
hugo new content posts/my-new-post/index.md
```

- Tags and categories are lowercase (`fleet`, not `Fleet`), or the site grows duplicate tag pages.
- Callouts are GitHub-style: `> [!NOTE]`, `> [!WARNING]`.
- Diagrams are fenced code with the `mermaid` language.
- Cover: add the post to `POSTS` in `scripts/gen_covers.py`, run `python3 scripts/gen_covers.py`. OINK picks up `cover.svg` from the bundle automatically.
- Links to files in `static/code/` use `/dirtyfrag-blog/code/<file>`.

## Upgrading the theme

```bash
hugo mod get github.com/pgsty/oink@latest && hugo mod tidy
```

## License

Content and the artifacts in `static/code/` are MIT-licensed. See [`LICENSE`](LICENSE).
