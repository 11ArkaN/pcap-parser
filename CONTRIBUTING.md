# Contributing

Thanks for your interest in contributing.

## Development setup

1. Install dependencies:

```bash
bun install
```

2. Run type-check and tests:

```bash
bunx tsc --noEmit
bun test
```

3. Build app:

```bash
bun run build
```

## Pull requests

- Keep changes focused and small.
- Ensure `bunx tsc --noEmit` and `bun test` pass.
- Update docs/tests when behavior changes.

## Code style

- Follow existing TypeScript/React style used in the repo.
- Prefer clear names and minimal, targeted changes.
