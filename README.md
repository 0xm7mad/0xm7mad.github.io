# m7mad.sec — portfolio & writeups site

A single-page cybersecurity portfolio with a markdown-driven writeup log, built for GitHub Pages.
No build step, no framework — one `index.html`, a `posts/manifest.json` index, and plain `.md` files.

## Files

- `index.html` — the home page (hero, focus areas, case log, terminal, contact)
- `post.html` — renders a single writeup, e.g. `post.html?slug=just-pdf`. Clicking a case log entry, or running `cat <slug>` in the terminal, opens this page.
- `assets/style.css` — shared styles for both pages
- `posts/manifest.json` + `posts/*.md` — your writeup content, as before

## Deploying

1. Copy everything in this folder into the root of your `0xm7mad.github.io` repo
   (or any repo you'll serve with GitHub Pages), replacing the old Hexo output.
2. Commit and push. GitHub Pages will serve `index.html` directly — nothing to build.

## Adding a writeup

1. Add a new file to `posts/`, e.g. `posts/my-new-case.md`, written in plain markdown.
2. Add a matching entry to `posts/manifest.json`:

```json
{
  "slug": "my-new-case",
  "title": "My New Case",
  "date": "2026-09-25",
  "category": "Real World",
  "tags": ["DFIR"],
  "excerpt": "One or two sentences shown in the case log list."
}
```

3. Push. The post appears in the case log immediately, newest first, filterable by category.

`slug` must match the filename (without `.md`). `category` becomes a filter chip automatically —
reuse `Real World`, `CTF`, or add new ones freely.

## Editing the five existing posts

`posts/crowdstrike-process-injection.md`, `ieee-jordan-ctf-2025.md`, `just-pdf.md`,
`ncsc-2025-reverse.md`, and `vulnerable-kernel-driver.md` are stubs pre-filled with the
metadata and excerpts from your current Hexo blog. Open each one and paste in the full
writeup content — headings, code blocks and tables already render correctly (see
`posts/how-to-write-a-post.md` for a quick reference, and feel free to delete that file
once you're comfortable).

## Customising

- Colors, fonts and layout tokens are all in the `<style>` block at the top of `index.html`.
- Update the email address in the `mailto:` links (currently a placeholder).
- The tool chips under "Focus areas" are hand-written in `index.html` — edit the
  `#tool-chips` block to match your current stack.
