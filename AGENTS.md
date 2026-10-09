# Repository Guidelines

## Project Structure & Module Organization

This macOS-first C++20 application uses Qt 6 Widgets, CMake, and Ninja. `src/main.cpp` is the entry point; `src/gui/` contains presentation.  Keep automated tests in `tests/`, small sanitized or synthetic captures in `tests/fixtures/`, and supporting documents in `docs/`. See [README.md](README.md) for dependencies and [PLAN.md](PLAN.md) for milestone acceptance criteria.

## Build, Test, and Development Commands

Run `cmake --preset debug`, `cmake --build --preset debug`, and `ctest --preset debug --output-on-failure` from the root. Shared `release` and `sanitizer` presets use the same commands. The sanitizer preset checks and enables address/undefined sanitizers. Launch `./build/debug/llm_interceptor.app/Contents/MacOS/llm_interceptor`; closing the window quits. Qt lifecycle tests run offscreen without capture privileges. The GUI supports live interface selection, bounded history, details, and filters. The GUI records PCAP, exports retained/displayed CSV rows, and replays offline sessions. Tests use temporary synthetic files and injected writer failures. See README for permissions. Keep personal dependency paths in ignored `CMakeUserPresets.json`.

## Coding Style & Naming Conventions

Use four spaces and `.clang-format`; format with `xcrun clang-format -i` followed by the changed C++ files. Use `PascalCase` types, `camelCase` functions/variables, and matching `.hpp`/`.cpp` filenames. Compiler warnings are the initial lint checks. Distinguish MAC addresses, IP addresses, interfaces, and ARP operations. Keep parsing, capture setup, storage, and output formatting separate.

## Testing & Milestone Review

Use Qt Test registered with CTest. Prefer deterministic offline tests; live-interface tests must be explicit and optional. Add tests for valid packets, truncation, malformed fields, and unsupported types as parsing is implemented.

During implementation, task subagents with review and testing at each milestone. Review resource ownership, packet bounds, thread safety, and acceptance criteria. Run relevant automated checks and report actual results, failures, and coverage gaps. Resolve findings and rerun affected checks before marking work complete.

Implementation agent GPT-6.1 Sol with Light efffort owns production code/build/docs; GPT-6.1 Sol with Light efffort owns tests. Scope reads to the relevant milestone files and use separate build directories. A separate GPT-6.1 Sol with Light efffort reviewer works alongside implementation and testing; collaborate throughout the milestone. These role scopes are instructions in a shared workspace, not filesystem isolation. Require all three COMPLETE votes before proceeding.

## Commit, Pull Request & Security Guidelines

Use focused, imperative commits. After each milestone meets its acceptance criteria and all three COMPLETE votes are recorded, commit the milestone changes and push the commit to the tracked remote branch; verify the push before reporting completion. PRs describe behavior, relevant issues, actual validation, and sample CLI output when applicable. Check `git status --short` and `git diff --check` before committing. Capture only authorized traffic. Never commit credentials, sensitive captures, or machine-specific settings; retain ignore rules for build output and recordings while allowing curated fixtures.
