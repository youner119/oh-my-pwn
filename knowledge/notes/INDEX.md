# notes/

Agent-curated wiki. Starts empty, grows over time as agents
(VulnHunter, StrategyAgent, Exploiter, Reverser) discover generic
insights while solving challenges, or as the user adds derived content
from `sources/`.

For policy and broader context see
[`knowledge/README.md`](../README.md) and the spec at
[`.omc/specs/deep-interview-knowledge-integration.md`](../../.omc/specs/deep-interview-knowledge-integration.md).

## Categories

- [lua/](lua/INDEX.md) — Lua 언어 / VM / bytecode (embedded interpreter, sandbox escape, custom VM)

## When you add a new note

1. **Decide the category.** Reuse an existing one if it fits;
   otherwise create a new directory `notes/<category>/`.
2. **Write the note.** `notes/<category>/<topic>.md`. Frontmatter is
   recommended but not required (template below).
3. **Update the category INDEX.** Add a one-line entry under the
   `## Entries` section of `notes/<category>/INDEX.md`. If the
   category is brand new, create that file first using the template
   below.
4. **Update this TOP-level INDEX.** Add a one-line entry under
   `## Categories` for the new category. Only needed the first time
   the category appears — subsequent notes in an existing category do
   not touch this file.

## Category INDEX template

A new category INDEX (`notes/<category>/INDEX.md`) should look like:

````markdown
# notes/<category>/

<one-line description of what this category covers>

## Entries

- [<topic>.md](<topic>.md) — <one-line summary>

## Related raw material

- vendor: `<vendor>/<file>.md`
- sources (if present): `sources/<id>/`
````

The `Related raw material` section is optional but useful for
cross-reference during grep. `sources/<id>` paths may not exist on
every machine — that is expected (graceful skip).

## Note frontmatter (optional)

````markdown
---
title: <topic>
tags: [<area>, <subarea>]
applies_to_glibc: ">= 2.27"        # optional
related_sources:
  - sources/<id>/<file>
related_writeups:
  - writeups/<ctf>/<chal>
case_studies:
  - <ctf-name> <year> <chal>
last_updated: <YYYY-MM-DD>
---

# <Topic>

(free prose)
````

Frontmatter is **not required.** When present, future indexing can
aggregate by tag / glibc version; when absent, full-text grep still
works.

## Graceful skip

If this file or any category INDEX references `sources/<id>` and the
path is absent on the current machine, **skip silently** — `sources/`
is git-ignored raw dump storage that may or may not be present.
