# OAuch Agent Notes

## Workspace entrypoint
- Solution: `src/OAuch/OAuch.sln`
- This root `AGENTS.md` is the repo-level guide for future agents working anywhere in the workspace.

## Solution structure
- `src/OAuch/OAuch` is the ASP.NET Core web app.
- `src/OAuch/OAuch.Database` contains the EF Core `DbContext` and entities.
- `src/OAuch/OAuch.Protocols` contains OAuth/OIDC/JWT/TLS protocol logic.
- `src/OAuch/OAuch.Shared` contains shared enums, settings, logging types, and interfaces.
- `src/OAuch/OAuch.OAuthThreatModel` contains the threat-model library.
- `src/OAuch/OAuch.Tests` is not a normal `dotnet test` project; it is a library of compliance/test definitions consumed by the app and related projects.

## Runtime and app behavior
- All projects in the solution target `net10.0`.
- `Nullable` is enabled across the projects, and several projects also set `LangVersion` to `latest`.
- The web app still uses the classic `Program` + `Startup` pattern.
- The app uses MVC with Razor views and maps a SignalR hub at `/testrunhub`.
- Local storage defaults to SQLite with `Data Source=oauch.db;` from `src/OAuch/OAuch/appsettings.json`.
- Docker switches the database path to `/db/oauch.db` via `src/OAuch/OAuch/appsettings.Docker.json`.
- Startup calls `db.Database.EnsureCreated()`; this repo currently relies on automatic database creation, not EF migrations.

## Local development
- README points developers to Visual Studio 2022 first, though manual `dotnet build` is also mentioned as possible.
- Because the solution now targets `net10.0`, local source builds require a .NET 10-capable SDK/toolchain.
- The launch profile runs with `ASPNETCORE_ENVIRONMENT=Development` and `applicationUrl` set to `https://oauch.io:443`.
- In `DEBUG`, `Program.cs` tries to load an HTTPS certificate from the Windows certificate store with subject `oauch.io`, then falls back to `localhost`.
- README expects a local hosts-file override of `127.0.0.1 oauch.io`; without that override, local browsing must be switched to `https://localhost/`.
- HSTS is intentionally disabled so non-`oauch.io` redirects keep working.
- Response compression is only enabled outside `DEBUG`, because the code comments note interference with Visual Studio's injected debug script.

## Build and tooling notes
- Build entrypoint: `dotnet build src/OAuch/OAuch.sln`
- In this environment, the build command that worked was: `& 'C:\Program Files\dotnet\dotnet.exe' 'C:\Program Files\dotnet\sdk\10.0.201\MSBuild.dll' src\OAuch\OAuch.sln /t:Build /p:Restore=False /v:minimal`
- There is no `global.json`, so `dotnet` chooses the machine-default SDK.
- In this environment, `dotnet --info` reported SDK `10.0.201` as the default, with .NET 10 runtimes installed.
- In this environment, plain `dotnet build src/OAuch/OAuch.sln` still exits with a restore failure before compilation when run in the sandbox.
- Invoking MSBuild explicitly from SDK `10.0.201` shows the immediate blocker here: restore cannot read `%AppData%\NuGet\NuGet.Config` because the sandbox denies access.
- For sandboxed CLI work here, assume you may need a workspace-local `DOTNET_CLI_HOME` and a readable local NuGet config before `restore` or `build` will succeed.
- Source-build instructions are still centered on `dotnet build src/OAuch/OAuch.sln`, but container-build instructions are not aligned until the Dockerfiles move off .NET 8 images.
- Do not add or update NuGet packages without the user's explicit permission.
- `git status` currently fails in this environment because the repo is not marked as a Git `safe.directory`.
- No CI workflow files were found under `.github/workflows`, so there is no repo-local CI definition to use as the source of truth.

## Repo conventions and gotchas
- Use English for all code comments, function names, and other code identifiers that are being introduced or renamed.
- `src/OAuch/.editorconfig` silences these diagnostics: `SYSLIB0039`, `CS0618`, `IDE0290`, `IDE0056`, `IDE0230`, `IDE0079`, `IDE1006`.
- `src/OAuch/OAuch/OAuch.csproj` has a `Date` target that writes a generated `gen.cs` file into `obj`; do not hand-edit generated intermediates.
- `docs/` contains OAuth/OpenID reference documents that explain many threat and test names used in the codebase.
- Both `src/OAuch/Dockerfile` and `src/OAuch/Dockerfile.multi` still use .NET 8 SDK/runtime images even though the solution targets `net10.0`; keep that version drift in mind before relying on container builds.
- There are no automated test cases to run yet as part of normal validation, so for generated code the default verification step is to build the solution and confirm the build result.

## Git workflow
- Never commit directly to `main` or `master`.
- Create a new branch for each task.
- Prefer branch names like `ai/<task-slug>`.
- Make local changes first; do not push automatically unless the user explicitly asks.
- Before committing, run relevant tests, lint, and type checks.
- Keep commits small and reviewable.
- Do not force-push unless explicitly requested.
- Do not open a PR until checks pass or failures are clearly explained.