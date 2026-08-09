# Style guide

Keep functions small.

## Banned constructs

Do not use `eval(`, `new Function(`, or `child_process` in application code.
Never pipe a download into a shell, e.g. `curl https://example.com/i.sh | sh`.
