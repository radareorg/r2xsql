# Stacked Pull Request Plan for r2xsql Plugin-Only Transition

This plan breaks down the transition from a multi-artifact project (CLI, HTTP server, MCP server, plugin) to a single in-radare2 core plugin into atomic commits suitable for stacked pull requests. Each commit is self-contained, builds, and passes tests. PRs should be stacked and merged bottom to top.

## Commit 1: Remove MCP Server Support
**Description:** Eliminate the fastmcpp-based MCP server code and all related build options, leaving only the core plugin and CLI (to be removed later).
**Files changed:**
- `src/common/mcp_server.cpp` (delete)
- `src/common/mcp_server.hpp` (delete)
- `CMakeLists.txt`: remove `R2XSQL_WITH_MCP` option, associated code, and fastmcpp FetchContent
- `src/CMakeLists.txt`: remove MCP-related conditionals
- `src/cli/main.cpp`: remove MCP includes, options, and runtime code
- `examples/CMakeLists.txt`: remove Windows-specific MCP DLL copy logic
- `prompts/r2xsql_agent.md`: remove MCP server sections
**Notes:** After this commit, the project still builds the pipe-only and full CLI flavors, but without MCP support.

## Commit 2: Remove HTTP Server Support
**Description:** Strip out the HTTP REST server implementation (thinclient/http_query_server) and related CLI options.
**Files changed:**
- `src/lib/include/r2xsql/http_query_server.hpp` (delete)
- `src/lib/src/http_query_server.cpp` (delete)
- `CMakeLists.txt`: remove HTTPLIB_USE_OPENSSL_IF_AVAILABLE force and related code
- `src/CMakeLists.txt`: remove HTTP server conditionals
- `src/cli/main.cpp`: remove HTTP includes, options, and runtime code
- `prompts/r2xsql_agent.md`: remove HTTP server sections
- `examples/CMakeLists.txt`: remove HTTP-related Windows DLL copy (if any)
**Notes:** CLI still present; HTTP server code removed.

## Commit 3: Remove CLI Tool Completely
**Description:** Delete the command-line interface (both pipe-only and full flavors) and retain only the plugin library.
**Files changed:**
- `src/cli/` directory (delete entire folder: CMakeLists.txt, main.cpp)
- `src/CMakeLists.txt`: remove CLI subdirectory conditional, keep only plugin subdirectory
- `CMakeLists.txt`: remove `R2XSQL_BUILD_CLI` and `R2XSQL_BUILD_FULL` options; remove libr backend conditionals tied to full flavor
- `src/lib/CMakeLists.txt`: remove `R2XSQL_FULL_ENABLED` guards; always build the libr backend as an OBJECT library
- `Makefile`: update test rule to load plugin via `-i` (already done in diff)
- `examples/CMakeLists.txt`: unconditionally link `r2xsql_libr` and `Radare2::libr` (remove `R2XSQL_FULL_ENABLED` condition)
- `meson.build`: update comment to reflect single artifact build
- `prompts/r2xsql_agent.md`: remove all CLI references, rewrite to plugin-only usage
**Notes:** Build system now configured to build only the core_r2xsql plugin. CLI binaries are no longer produced.

## Commit 4: Update Build System for Mandatory Radare2 Dependency
**Description:** Make radare2 a hard requirement (no fallback), simplify PIC and MSVC runtime checks, and update version messaging.
**Files changed:**
- `CMakeLists.txt`: 
  - Remove `R2XSQL_BUILD_FULL` logic
  - Make `Radare2` package mandatory (FATAL_ERROR if not found)
  - Remove `R2XSQL_BUILD_CLI`, `R2XSQL_WITH_MCP`, `R2XSQL_BUILD_EXAMPLES` options
  - Keep PIC setting and MSVC static CRT check (now applies to plugin)
  - Update status messages
- `src/lib/CMakeLists.txt`: remove conditional compilation of libr backend; always build with `R2XSQL_HAVE_LIBR=1`
- `src/lib/src/backend_libr.cpp` and `direct_libr.cpp`: ensure they compile unconditionally
**Notes:** Configuration now fails if radare2 is not found; plugin always links against libr.

## Commit 5: Update CI Workflows to Build and Release Only Plugin
**Description:** Modify GitHub Actions to build a single plugin artifact per platform and adjust upload/release steps.
**Files changed:**
- `.github/workflows/build.yml`:
  - Remove matrix builds for CLI flavors
  - Single job per OS building only the core_r2xsql plugin
  - Update artifact names to `*-plugin`
  - Update upload steps accordingly
  - Adjust release step to upload only three plugin zips (Linux, Windows, macOS)
- `.github/scripts/stage_artifacts.sh`:
  - Simplify to create only `dist/plugin/` directory
  - Update README.txt content to reflect plugin-only usage
  - Remove overlay and pipe-only directories and files
**Notes:** CI now produces exactly one artifact per platform: the radare2 plugin.

## Commit 6: Update Documentation and Prompts
**Description:** Rewrite user-facing documentation to reflect plugin-only usage, commands, and workflows.
**Files changed:**
- `README.md`: (if not already updated in diff) update to describe plugin-only installation and usage
- `prompts/r2xsql_agent.md`: already rewritten in diff; ensure it matches final state
- Any other `.md` or documentation files: remove references to CLI, HTTP, MCP
**Notes:** Focus on `sql` and `sqlj` commands, usage examples, and notes about quoting and analysis.

## Commit 7: Cleanup Miscellaneous Files and References
**Description:** Remove leftover configuration files, ignore patterns, and dead code.
**Files changed:**
- `.gitignore`: add `/subprojects/.wraplock` (as in diff) and remove any ignored CLI/build artifacts
- `src/lib/src/`: audit table adapter files for removal of `r2xsql_type_define` calls and replace with radare2 `td` command where appropriate (per diff comments)
- `tests/`: ensure test suite uses the new plugin-only invocation (r2r under `tests/db/extras/cmd/`)
- `LICENSE`, etc.: no change unless needed
**Notes:** This commit ensures no dangling references to removed features remain.

## Commit 8: Final Verification and Test Update
**Description:** Verify that the plugin builds, loads in radare2, and passes the updated test suite.
**Files changed:**
- Possibly update `tests/` if needed to match new plugin behavior (e.g., adjust expectations for `sqlj` output)
- Update any CI test steps to run the plugin-only test command: `make -C tests R2XSQL_PLUGIN_DIR=<build>/bin`
**Notes:** After this commit, the project is ready for release as a single in-radare2 plugin.

## Summary
Each commit above is atomic, focuses on a single concern, and maintains compilability. The stacked PR approach allows reviewing each incremental change (e.g., "Remove MCP", "Then HTTP", "Then CLI", etc.) and merging from bottom to top ensures a smooth transition.