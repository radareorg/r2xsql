# Using r2xsql with radare2 and an agent

The plugin supplies SQL over a live radare2 core. The skills teach an agent
how to choose tables, query and annotate that core, and manage its lifetime.
The user can ask in natural language in either tandem or headless mode.

## Installation

Install radare2, then install a matching r2xsql plugin:

```sh
r2pm -U
r2pm -ci r2xsql
```

Installed plugins load automatically on normal startup. `make user-install`
does the same for a local build. Manual installation uses the directory
reported by `r2 -NN -H R2_USER_PLUGINS`. Restart a host after installation.
The plugin's radare2 ABI must match the engine loading it; iaito can use a
different engine from the standalone r2 on PATH. Binary installation with
`r2pm -bi r2xsql` requires an available asset matching the host and platform,
plus r2pm with `R2PM_VERSION_MAP` support (radare2 git; planned for 6.2.6).
See [building and packaging](development.md).

For a build that is not installed:

```sh
r2 -i ./core_r2xsql.so -A ./target
```

Use the actual `.so`, `.dylib` or `.dll` file. `-i` also accepts native r2
command scripts. Inside an existing console, load a plugin with
`L ./core_r2xsql.so`; `L r2xsql` is not a package-name loader.
`-N` skips startup scripts while retaining plugins; `-NN` disables automatic
plugin loading too. For a deterministic local-build check, use `-NN -i FILE`.
Verify `r2xsql` in `Lcj`, then try `sql?` and `sqlj SELECT 1`.

Install the [r2xsql skills](https://github.com/radareorg/radare2-skills/tree/main/r2xsql#install)
in the coding agent's harness. Skills and the binary plugin are separate
installations. The harness selects the `r2xsql` entry skill and routes to
connection and domain instructions; explicit skill selection can be used
when the harness does not select it automatically.

## Tandem mode

Tandem shares an existing analysis in an interactive r2 CLI, its visual/panels
text interface, or [iaito](https://github.com/radareorg/iaito). For a fresh
binary run `r2 -A ./target`, or open it in iaito and let analysis finish.
For a saved project run `r2 -p PROJECT` without `-A`.

At the r2 prompt or iaito's **View > Console**, verify the plugin with `Lcj`,
then start background HTTP:

```text
e http.bind=127.0.0.1
e http.sandbox=false
e http.port=9090
=h&
```

Choose a free port. `http.port` selects it; `=h&` starts the background
server and leaves the console/UI available. It is an alias for `& =h`,
using r2's background-task facility. `=h` serves in the foreground instead.
Start HTTP at the prompt before entering the text interface.

Wait for `open http://127.0.0.1:9090/`, then tell the agent:

> Use r2xsql at http://127.0.0.1:9090 on the binary already open here.
> Show me the largest functions.

The agent checks the host, plugin and binary identity, authors SQL and reuses
the endpoint on later questions. It should not open another UI or rerun
analysis merely to attach. Renames and comments affect the human's analysis
too. Take turns with the agent when running analysis-changing native commands.
Use `=h-` at the interactive console to stop background HTTP while keeping
the human's host open.

For several hosts, select a distinct port per process and provide a mapping:
**application = http://127.0.0.1:9090, library = http://127.0.0.1:9091**.
The agent verifies each target and labels findings by source. SQL executes
inside one host; comparisons across hosts combine results in the client.

## Fully headless

With the plugin installed, an agent can start the native r2 process without
a human console or GUI. For a fresh binary, POSIX shell:

```sh
r2 -N -q -A -e scr.html=false -e http.bind=127.0.0.1 \
  -e http.sandbox=false -e http.port=9090 -c '=h' ./target \
  >r2.stdout.log 2>r2.stderr.log &
r2_pid=$!
```

Windows PowerShell:

```powershell
$engine = Get-Command r2,radare2 -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $engine) { throw 'Install radare2 or supply its executable location.' }
$target = (Resolve-Path -LiteralPath '.\target.exe').Path
$port = 9090 # choose a free port
$logDir = Join-Path $env:TEMP ('r2-session-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $logDir | Out-Null
$arguments = '-N -q -A -e scr.html=false -e http.bind=127.0.0.1 -e http.sandbox=false -e http.port={0} -c "=h" "{1}"' -f $port,$target
$process = Start-Process -FilePath $engine.Source -ArgumentList $arguments -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $logDir 'stdout.log') `
    -RedirectStandardError (Join-Path $logDir 'stderr.log') -PassThru
$endpoint = 'http://127.0.0.1:{0}/cmd/' -f $port
```

These launch radare2 directly. No Python session/query wrapper or build
orchestrator is needed. `-A` runs analysis once; foreground `=h` keeps the
background OS process alive. Queries use that same core until shutdown.
For an uninstalled plugin, substitute `-NN -i PLUGIN_FILE` for `-N`.

Wait for the server banner on stderr, then verify the endpoint with curl.
A bind failure is not readiness. Retain the PID, endpoint, binary/project
and log locations; subsequent prompts reuse this session.

## HTTP queries

For radare2 **6.2.4**, POST the complete r2 command to `/cmd/`:

```sh
curl -d '?V' http://127.0.0.1:9090/cmd/
curl -d 'Lcj' http://127.0.0.1:9090/cmd/
curl -d '"sqlj SELECT * FROM binary"' http://127.0.0.1:9090/cmd/
curl -d '"sqlj SELECT name,size FROM funcs WHERE size > 100 LIMIT 5"' \
  http://127.0.0.1:9090/cmd/
```

In PowerShell use `curl.exe` to avoid the shell alias:

```powershell
$command = '"sqlj SELECT name,size FROM funcs ORDER BY size DESC LIMIT 10"'
curl.exe --silent --show-error --max-time 30 -d $command $endpoint
```

The body is an r2 command. The **double quotes are part of that body** and
protect SQL operators such as `>` and `|` from r2's parser. Use `sqlj`
for the JSON envelope; `sql,:json` is a table format with different NULL and
empty-string behavior. Inspect top-level and per-statement success/error
fields; HTTP 200 alone does not establish success. See [SQL access](sql.md).
Native commands such as `pdf` and `Ps` travel over the same endpoint.

The command-prefix-plus-body form is implemented in development radare2
and is planned for **6.2.6**:

```sh
curl -d 'SELECT name,size FROM funcs ORDER BY size DESC LIMIT 5' \
  http://127.0.0.1:9090/cmd/sqlj
```

Here the URL selects `sqlj` and the body contains only SQL. This is a
version-dependent alternative, not a 6.2.4 example. Use the full-command
form until the host is known to support it. An agent should verify the JSON
response to a harmless query before choosing this form for mutations.
The combined command still passes through r2's parser. For SQL containing
operators such as `>` or `|`, keep the full double-quoted command form above.

## Saving and reopening

Analysis lives in memory until saved. Ask the agent to save the project beside
the binary, or select another location. The save operation is native radare2;
there is no SQL `save_database()` in r2xsql.

```sh
curl -d 'Ps /absolute/path/target.exe.r2' http://127.0.0.1:9090/cmd/
```

PowerShell, using the absolute target path from the launch:

```powershell
$project = ($target + '.r2').Replace('\','/')
curl.exe --silent --show-error --max-time 30 -d ('Ps ' + $project) $endpoint
Get-Item -LiteralPath $project
```

Use forward slashes in native r2 commands on Windows. Verify the actual saved
artifact, host log and requested annotations; a refused save can return an
empty HTTP 200. Keep the original binary and any companion `.r2.d` directory.
Saving analysis does not patch the executable or shut down the host.

Reopen the saved project with `-p`, without a separate target or reanalysis:

```sh
r2 -N -q -p /absolute/path/target.exe.r2 \
  -e scr.html=false -e http.bind=127.0.0.1 \
  -e http.sandbox=false -e http.port=9090 -c '=h' \
  >r2.stdout.log 2>r2.stderr.log &
```

The project stores the binary path. On Windows replace `-A` and the target
in the launch arguments with `-p "PROJECT"`; keep the same `-e` options
and `-c "=h"`. Verify binary identity and saved annotations after reopening,
rather than checking only function counts. Preserve the checkpoint and logs
if verification fails.

### Projects and command scripts

Native projects support binary serialization and script compatibility; do not
infer their format from the filename alone. `Ps PROJECT` and `-p PROJECT`
are the normal save/reopen interface. A bare project name uses `dir.projects`;
an absolute filename selects a sidecar. `Pl` lists named projects, not every
sidecar elsewhere.

Where available, `prj?` documents the binary-container operations, including
`prj save FILE` and `prj open FILE`. Select the matching native loader for
an existing container; a standalone container is not interchangeable with a
named `-p` project on every host. Explicit command-script exports use `PS`
or `PS*` and can be interpreted with `-i SCRIPT`; they are not a reason to
describe all projects as scripts. Check `P?` and `prj?` on the chosen host.

## Shutdown and session ownership

On a save-and-shutdown request, save and verify first, then stop an agent-owned
foreground server:

```sh
curl 'http://127.0.0.1:9090/cmd/=h--'
```

`=h--` is intercepted in the GET path; putting it in a POST body does not
stop that accept loop. With the headless `-q` launch and no later commands,
r2 exits when serving ends. Verify the intended PID and listener stopped.
Do not close the user's tandem UI; stop its background server at the console
only when requested. Saving alone leaves the host available for follow-ups.

The server provides local command access, including writes when
`http.sandbox=false`. Bind to `127.0.0.1` and do not expose it as a public
service.
