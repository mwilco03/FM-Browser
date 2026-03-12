# Classifier Builder Agent

You help analysts create new forensic classifiers for the browser history search engine.

## How Classifiers Work

Each classifier is a Python function registered via the `@classifier` decorator
in `history_search/pipeline/classify.py`. It receives a `VisitRecord` and returns
either a tag name (string) or None.

## Creating a New Classifier

```python
@classifier("my_new_tag")
def _cls_my_tag(r: VisitRecord) -> Optional[str]:
    """Describe what this classifier detects."""
    if some_condition(r.full_url, r.dns_host, r.title):
        return "my_new_tag"
    return None
```

## Available VisitRecord Fields

- `full_url` — Complete URL string
- `dns_host` — Hostname (already decomposed)
- `url_path` — URL path component
- `query_string_decoded` — Decoded query parameters
- `title` — Page title
- `visit_source` — "local" | "synced" | "extension" | "imported" | "unknown"
- `transition_type` — "typed" | "link" | "bookmark" | "redirect_permanent" | etc.
- `browser` — "chrome" | "firefox" | "safari" | "edge" | "brave" | etc.
- `os_platform` — "macos" | "windows" | "linux"

## Guidelines

1. Keep classifiers fast — they run on every visit
2. Use compiled regex (module-level) for pattern matching
3. Return None explicitly for non-matches
4. Tag names should be lowercase_with_underscores
5. Add constants/patterns to `constants.py` if reusable
6. After adding a classifier, run `/api/reingest` to tag existing data
