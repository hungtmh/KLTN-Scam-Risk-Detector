# Repository Agent Notes

This repository is configured for GitHub Spec Kit with the Codex integration.

Use the local Spec Kit skills in `.agents/skills/` when the user asks for spec-driven work:

- `$speckit-constitution` for project principles.
- `$speckit-specify` for feature specifications.
- `$speckit-plan` for implementation planning.
- `$speckit-tasks` for task breakdown.
- `$speckit-implement` for implementation.
- `$speckit-clarify`, `$speckit-analyze`, and `$speckit-checklist` for optional quality gates.

In the Codex VS Code extension, do not expect `/speckit.*` slash commands. Those are for GitHub Copilot. Codex built-in slash commands remain things like `/status`, `/plan`, and `/review`; Spec Kit is invoked as skills with `$speckit-*` or by explicitly asking Codex to use a named Spec Kit skill.
