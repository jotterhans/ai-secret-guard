# ai-secret-guard

A hook for coding agents that stops passwords, API keys and connection strings from being sent to the model.

It works with Claude Code, OpenAI Codex CLI, Gemini CLI, Cursor and GitHub Copilot CLI. It runs on Linux, macOS and Windows.

It is one Python file. It uses only the standard library, makes no network calls and writes no logs.

## Why

Everything you type into a coding agent, and everything a tool reads or prints, is sent to the model. Most agents also save it in a session transcript on disk (Claude Code uses `~/.claude/projects/*.jsonl`). A secret that gets there once is out of your control:
- clearing the chat does not remove it from the transcript on disk;
- deleting the transcript does not remove it from the provider's side;
- the only real fix is to change the secret.

Secrets usually reach the model in a few ordinary ways:
- a connection string pasted into a message to "set it up";
- the agent opening `.env` or a `*.local.json` file to "check the configuration";
- a command with the password written inline, for example `psql "postgresql://user:pass@host/db"`;
- the agent writing a real key into a source file.

secret-guard stops each of these before it happens. It is meant as a seat belt, not as a vault.

## How it works

The agent runs the script before it sends your message, and before it runs a tool. The script reads the hook input as JSON on stdin. It finds the agent from the shape of the input, or from the `--agent claude|codex|gemini|cursor|copilot` argument. It maps the event and the tool to one of four checks:

| Check | What secret-guard checks | What happens on a match |
|---|---|---|
| prompt | the text of your message | The message is not sent to the model. The reason is shown to you. |
| read | a read, search or list of a secret file | The call is denied. The model gets the reason. |
| shell | a command that holds a secret, or that prints a secret file (`cat`, `type`, `Get-Content`, `head`, `grep`, `jq` and so on) | The call is denied. |
| write | a write, edit or patch to a secret file, or with text that holds a secret | The call is denied. The model is told to write a placeholder and read the value from the environment. |

The reply uses the block format of each agent. The messages name the kind of secret, for example "a URL with a password", and never its value.

### What each agent can block

| Agent | prompt | read | shell | write | Hook docs |
|---|---|---|---|---|---|
| Claude Code | Yes (`UserPromptSubmit`, exit 2) | Yes (`Read`, `Grep`, `Glob`, `NotebookEdit`) | Yes (`Bash`, `PowerShell`) | Yes (`Write`, `Edit`, `MultiEdit`) | [code.claude.com/docs/en/hooks](https://code.claude.com/docs/en/hooks) |
| OpenAI Codex CLI | Yes (`UserPromptSubmit`, exit 2) | Through the shell check only. Codex reads files with shell commands. | Yes (`Bash`) | Yes (`apply_patch`: target paths and added lines) | [developers.openai.com/codex/hooks](https://developers.openai.com/codex/hooks) |
| Gemini CLI | Yes (`BeforeAgent`, `decision: "deny"`; the message is not kept in history) | Yes (`read_file`, `read_many_files`, `grep_search`, `glob`, `list_directory`) | Yes (`run_shell_command`) | Yes (`write_file`, `replace`) | [geminicli.com/docs/hooks/reference](https://geminicli.com/docs/hooks/reference/), [tools](https://geminicli.com/docs/reference/tools/) |
| Cursor | Yes (`beforeSubmitPrompt`, `continue: false`) | Yes (`beforeReadFile`). It also checks the file content. | Yes (`beforeShellExecution`) | No. Cursor has no hook before a file edit. | [cursor.com/docs/agent/hooks](https://cursor.com/docs/agent/hooks) |
| GitHub Copilot CLI | No. Copilot drops the output of prompt hooks in config files. | Partly (see below) | Yes (`bash`, `powershell`) | Partly (see below) | [docs.github.com hooks reference](https://docs.github.com/en/copilot/reference/hooks-configuration) |

Copilot CLI: the docs show only the `bash` tool and its `command` argument. For other tools, secret-guard checks any `path`, `file_path`, `content`, `new_str` or `file_text` argument. This part is not verified against the docs.

### What counts as a secret

- URLs with `user:password@`, for example `postgresql://`, `mongodb+srv://` and `https://`;
- `Password=` or `Pwd=` in connection strings;
- `PGPASSWORD`, `MYSQL_PWD`, and variables ending in `PASSWORD`, `SECRET`, `TOKEN` or `API_KEY`, when they are given a value;
- `"password"`, `"secret"`, `"token"`, `"api_key"` and `"client_secret"` fields in JSON;
- Anthropic keys, OpenAI-style keys, GitHub tokens, AWS access keys, Slack tokens and Google API keys;
- Azure storage account keys and SAS signatures (`sig=`);
- JSON web tokens and private key blocks.

Placeholders are allowed, so documentation and examples still work. Examples are `<password>`, `${DB_PASS}`, `$env:X`, `%X%`, `pw`, `changeme`, `example`, `xxx` and `***`.

### What counts as a secret file

- `.env` and `.env.*`, and `*.local.json`;
- `secrets*` and `*secret*.json`;
- `*.pem`, `*.key`, `*.pfx`, `*.p12` and `id_rsa*`;
- `.pgpass`, `.netrc`, `.git-credentials`, `credentials.json` and `*.kdbx`;
- WireGuard `wg*.conf`;
- any file under `.ssh`, `.aws`, `.azure`, `.gnupg` or `.docker`.

Files named `*.example`, `*.sample`, `*.template` or `*.pub` are allowed. Paths with `/` and `\` both work. A leading `~` is expanded to your home folder.

## Install

1. Copy `secret_guard.py` to a stable place. The sections below use the config folder of each agent. It needs Python 3.8 or later.
2. Add the hook to the config file of your agent, as shown below. Use the full path to the script.
3. Start a new session.

### Python command

- Linux and macOS: use `python3`.
- Windows: use `python`, or the launcher `py -3`. `python3` often opens the Microsoft Store instead.

The examples use `python3` and `~`. On Windows, use `python` and the full path, for example `C:/Users/<you>/.codex/hooks/secret_guard.py`. Forward slashes work in Windows paths.

### Claude Code

Config file: `~/.claude/settings.json` (all projects) or `.claude/settings.json` (one project). On Windows, `~` is `%USERPROFILE%`.

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [ { "type": "command", "command": "python3 ~/.claude/hooks/secret_guard.py" } ] }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Read|Grep|Glob|Edit|Write|MultiEdit|NotebookEdit",
        "hooks": [ { "type": "command", "command": "python3 ~/.claude/hooks/secret_guard.py" } ]
      }
    ]
  }
}
```

Run `/hooks` to check that the hooks are loaded. On Windows, Claude Code runs the command in Git Bash, or in PowerShell when Git Bash is not installed.

### OpenAI Codex CLI

Config file: `~/.codex/hooks.json` (all projects) or `<repo>/.codex/hooks.json` (one project). On Windows, `~` is `%USERPROFILE%`. Hooks are on by default. Codex runs a hook only after you review and trust it with `/hooks`.

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [ { "type": "command", "command": "python3 ~/.codex/hooks/secret_guard.py --agent codex",
                     "commandWindows": "python C:/Users/<you>/.codex/hooks/secret_guard.py --agent codex" } ] }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash|apply_patch",
        "hooks": [ { "type": "command", "command": "python3 ~/.codex/hooks/secret_guard.py --agent codex",
                     "commandWindows": "python C:/Users/<you>/.codex/hooks/secret_guard.py --agent codex" } ]
      }
    ]
  }
}
```

You can also put the same hooks in `[hooks]` tables in `~/.codex/config.toml`.

### Gemini CLI

Config file: `~/.gemini/settings.json` (all projects) or `.gemini/settings.json` (one project). On Windows, `~` is `%USERPROFILE%`.

```json
{
  "hooks": {
    "BeforeAgent": [
      { "hooks": [ { "name": "secret-guard", "type": "command", "command": "python3 ~/.gemini/hooks/secret_guard.py --agent gemini" } ] }
    ],
    "BeforeTool": [
      {
        "matcher": "read_file|read_many_files|grep_search|search_file_content|glob|list_directory|write_file|replace|run_shell_command",
        "hooks": [ { "name": "secret-guard", "type": "command", "command": "python3 ~/.gemini/hooks/secret_guard.py --agent gemini" } ]
      }
    ]
  }
}
```

### Cursor

Config file: `~/.cursor/hooks.json` (all projects) or `<project>/.cursor/hooks.json` (one project). On Windows, `~` is `%USERPROFILE%`, and Cursor runs the command in PowerShell.

```json
{
  "version": 1,
  "hooks": {
    "beforeSubmitPrompt": [ { "command": "python3 ~/.cursor/hooks/secret_guard.py --agent cursor" } ],
    "beforeReadFile": [ { "command": "python3 ~/.cursor/hooks/secret_guard.py --agent cursor" } ],
    "beforeShellExecution": [ { "command": "python3 ~/.cursor/hooks/secret_guard.py --agent cursor" } ]
  }
}
```

Cursor blocks the action when a permission hook prints invalid JSON. So secret-guard always prints an answer to Cursor, also when it allows the call.

### GitHub Copilot CLI

Config file: any `*.json` file in `~/.copilot/hooks/` (all projects) or in `.github/hooks/` (one repository). On Windows, the user folder is `%USERPROFILE%\.copilot\hooks\`. Copilot runs `bash` on Linux and macOS and `powershell` on Windows.

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "python3 \"$HOME/.copilot/hooks/secret_guard.py\" --agent copilot",
        "powershell": "python \"$env:USERPROFILE\\.copilot\\hooks\\secret_guard.py\" --agent copilot"
      }
    ]
  }
}
```

### Other agents

secret-guard needs a hook that runs before a tool call and can block it. If your agent has no such hook, use its own controls instead: deny rules for secret files, a sandbox, and approval for every command. For example, Codex has `sandbox_mode` and `approval_policy` in `config.toml`, and Claude Code has `permissions.deny`.

### Check it by hand

```sh
echo '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":".env"}}' | python3 secret_guard.py
echo '{"hook_event_name":"BeforeTool","tool_name":"read_file","tool_input":{"file_path":".env"}}' | python3 secret_guard.py
```

Each command prints a deny reply.

## Settings

| Environment variable | Effect |
|---|---|
| `SECRET_GUARD_FILES` | Extra secret-file globs, separated by `;`. Example: `*/config/prod.json;*/tenants/*.json` |
| `SECRET_GUARD_OFF=1` | Switches the hook off |

The older names `CLAUDE_SECRET_GUARD_FILES` and `CLAUDE_SECRET_GUARD_OFF` still work.

## Limits

secret-guard matches patterns, and some things are outside its view:

- **Commands you run yourself.** Commands you run in the agent with a shell prefix (for example `!` in Claude Code) do not go through hooks, and their output enters the conversation. Never put a secret in one.
- **Programs that print secrets.** A script that reads a secret file and prints it, such as `python show_config.py`, looks harmless to the hook.
- **Unlabelled secrets.** A random password with no label next to it cannot be recognized as a secret.
- **Tool output.** The hook does not rewrite what a tool returns. Only Cursor gives the file content to the hook before the read.
- **Agent gaps.** See the table above. Copilot CLI cannot block a prompt, and Cursor cannot block a file edit.

For a full scanner, see [gitleaks](https://github.com/gitleaks/gitleaks), [GitGuardian ggshield](https://github.com/GitGuardian/ggshield) (it has a Claude Code integration and needs an account) or [agent-guard](https://github.com/JeongJaeSoon/agent-guard). Permission deny rules and the sandbox of your agent add protection at the operating-system level.

## Keeping secrets out of the chat

Set a secret in your own terminal, not in the agent, and give the agent only the name of the variable.

PowerShell:

```powershell
$s = Read-Host "Value" -AsSecureString
[Environment]::SetEnvironmentVariable('MY_DB_URL', [Net.NetworkCredential]::new('', $s).Password, 'User')
```

bash:

```sh
read -rs MY_DB_URL && export MY_DB_URL
```

If a secret has reached the model, change the secret first. Then delete the session transcript that holds it.

## Tests

```sh
python3 -m unittest -q test_secret_guard
```

The tests use the input and output shapes from the hook docs of each agent. The test values are built from parts, so the test file itself does not trip secret scanners.

## License

MIT. See [LICENSE](LICENSE).
