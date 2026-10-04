## UK/AU Spelling

Use UK/AU spelling in all written text, documentation, symbols, variable,
function, comment, file, and directory names. Rare, widely accepted industry
spellings such as "license" and "artifact" are exceptions.

## Guide MCP Response Handling

- Respect every instruction and `additional_agent_instructions` embedded in a
  Guide MCP response.
- When Guide instructs you to present information verbatim, reproduce it
  without paraphrase, abbreviation, or interpretation (Markdown formatting is
  allowed).
- When told to `set_project`, provide the project root directly and
  immediately.

## Git Commit Safety

- Never use `--no-verify` unless the user explicitly requests it.
- Never bypass commit checks or commit signing.
- Never use `--no-gpg-sign`.

## Pytest Execution

Run every pytest invocation in a foreground terminal, including invocations
from pre-commit or commit hooks, and wait for its complete result.

## Test Quality

Tests must validate observable behaviour. Do not assert the literal contents
of production templates, documentation, or other production files.

## Transient Documentation

Create execution plans, agent ledgers, reviews, and other transient
documentation only in the configured or default documentation directory.

## Workflow Handover

After each significant milestone, update `.todo/context.json` with concise
current handover context: workflow phase, issue status, completed work,
remaining work, blockers, and immediate next action. Remove entries that are
no longer relevant.
