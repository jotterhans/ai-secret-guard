#!/usr/bin/env python3
"""secret-guard: a coding-agent hook that stops secrets from reaching the model (MIT).

Agents: Claude Code, OpenAI Codex CLI, Gemini CLI, Cursor and GitHub Copilot CLI. The agent is found from the
hook input, or given with --agent claude|codex|gemini|cursor|copilot. Each call maps to one of four checks:
  - prompt: a message that holds a secret is blocked before it is sent;
  - read:   reading or searching a secret file (.env, *.local.json, secrets*, keys, .ssh, ...) is denied;
  - shell:  a command that holds a secret, or that prints a secret file (cat, type, Get-Content, ...), is denied;
  - write:  a write, edit or patch that targets a secret file, or whose text holds a secret, is denied.
The reply uses the block format of the calling agent.

Standard library only, Python 3.8+. Extra secret-file globs: env variable SECRET_GUARD_FILES (or
CLAUDE_SECRET_GUARD_FILES), separated by ';'. SECRET_GUARD_OFF=1 (or CLAUDE_SECRET_GUARD_OFF=1) switches it off.
The message names the kind of secret, never its value; nothing is logged.
"""
import fnmatch
import json
import os
import re
import sys

AGENTS = ('claude', 'codex', 'gemini', 'cursor', 'copilot')

PLACEHOLDER = re.compile(
    r'^(?:[x*.\-_]+|<[^>]*>|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_]+%|\{[^}]*\}|\.\.\.|'
    r'pw|pwd|pass|password|secret|token|changeme|example|placeholder|redacted|your[_-]?\w*|xxx+|dummy|test|fake|sample)$',
    re.I)

# (kind, regex, group holding the value to compare with PLACEHOLDER, or None)
PATTERNS = [
    ('a private key', re.compile(r'-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----'), None),
    ('an Anthropic API key', re.compile(r'\bsk-ant-[A-Za-z0-9_\-]{20,}'), None),
    ('an OpenAI-style API key', re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}'), None),
    ('a GitHub token', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})'), None),
    ('an AWS access key', re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), None),
    ('a Slack token', re.compile(r'\bxox[abposr]-[A-Za-z0-9-]{10,}'), None),
    ('a Google API key', re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'), None),
    ('an Azure storage key', re.compile(r'AccountKey=([A-Za-z0-9+/=]{40,})', re.I), 1),
    ('an Azure SAS signature', re.compile(r'[?&]sig=([A-Za-z0-9%+/=]{20,})', re.I), 1),
    ('a JSON web token', re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'), None),
    ('a URL with a password', re.compile(r'\b[a-z][a-z0-9+.\-]*://[^\s:/@\'"]+:([^\s@/\'"]{3,})@', re.I), 1),
    ('a connection-string password', re.compile(r'\b(?:Password|Pwd)\s*=\s*([^;\s\'"]{4,})', re.I), 1),
    ('a password variable', re.compile(
        r'\b(?:PGPASSWORD|MYSQL_PWD|[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY))\s*[:=]\s*[\'"]?([^\s\'"]{6,})',
        re.I), 1),
    ('a password in JSON', re.compile(
        r'"(?:password|passwd|pwd|secret|token|api[_-]?key|client_secret)"\s*:\s*"([^"]{6,})"', re.I), 1),
]

SECRET_FILES = [
    '.env', '.env.*', '*.env', '*.local.json', 'secrets*', '*secret*.json', '*.pem', '*.key', '*.pfx', '*.p12',
    'id_rsa*', 'id_ed25519*', 'id_ecdsa*', '.pgpass', '.netrc', '.git-credentials', 'credentials', 'credentials.json',
    '*.kdbx', 'wg*.conf',
]
SAFE_FILES = ['*.example', '*.example.*', '*.sample', '*.sample.*', '*.template', '*.pub']
SECRET_DIRS = ['.ssh', '.aws', '.azure', '.gnupg', '.docker']
PRINTERS = (r'(?:cat|type|more|less|head|tail|bat|gc|get-content|select-string|findstr|grep|rg|strings|xxd|od|'
            r'base64|sed|awk|cp|copy|jq)')

# Tool name -> check, per agent. Names come from each agent's hook and tool docs.
SHELL_TOOLS = {'Bash', 'PowerShell', 'run_shell_command', 'bash', 'powershell', 'shell', 'exec_command'}
READ_TOOLS = {'Read', 'Grep', 'Glob', 'NotebookRead',
              'read_file', 'read_many_files', 'grep_search', 'search_file_content', 'glob', 'list_directory'}
WRITE_TOOLS = {'Edit', 'Write', 'MultiEdit', 'NotebookEdit', 'write_file', 'replace'}
PATCH_TOOLS = {'apply_patch'}
PATH_KEYS = ('file_path', 'notebook_path', 'path', 'absolute_path', 'dir_path', 'include_pattern', 'include', 'paths')
TEXT_KEYS = ('content', 'new_string', 'new_str', 'file_text', 'new_source')


def _env(name):
    return os.environ.get('SECRET_GUARD_' + name) or os.environ.get('CLAUDE_SECRET_GUARD_' + name) or ''


def _value_is_secret(value):
    return not PLACEHOLDER.match(value.strip())


def secret_in(text):
    """The kind of the first real secret in text, or None."""
    for kind, rx, group in PATTERNS:
        for m in rx.finditer(text or ''):
            if group is None or _value_is_secret(m.group(group)):
                return kind
    return None


def _norm(path):
    """Path with ~ expanded and / as the only separator, so Windows and POSIX paths match alike."""
    return os.path.expanduser(str(path).strip()).replace('\\', '/').rstrip('/')


def secret_file(path):
    if not path:
        return False
    norm = _norm(path)
    base = norm.split('/')[-1].lower()
    if any(fnmatch.fnmatch(base, g) for g in SAFE_FILES):
        return False
    if any(fnmatch.fnmatch(base, g) for g in SECRET_FILES):
        return True
    extra = [g for g in _env('FILES').split(';') if g.strip()]
    if any(fnmatch.fnmatch(norm.lower(), _norm(g).lower()) for g in extra):
        return True
    return any(d in [p.lower() for p in norm.split('/')[:-1]] for d in SECRET_DIRS)


def command_reads_secret_file(cmd):
    """The secret file a command would print, or None."""
    if not re.search(r'(?:^|[\s;|&(])' + PRINTERS + r'(?:\.exe)?(?=\s)', cmd or '', re.I):
        return None
    for quoted_d, quoted_s, bare in re.findall(r'"([^"]+)"|\'([^\']+)\'|(\S+)', cmd):
        word = (quoted_d or quoted_s or bare).strip('();|&<>')
        if word and not word.startswith('-') and secret_file(word):
            return word
    return None


def _strings(value):
    """A flat list of the strings in value (a string, or a list of strings)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [v for v in value if isinstance(v, str)]
    return []


def _paths(inp):
    return [p for k in PATH_KEYS for p in _strings(inp.get(k))]


def _text(inp):
    parts = [s for k in TEXT_KEYS for s in _strings(inp.get(k))]
    parts += [e.get('new_string', '') for e in inp.get('edits') or [] if isinstance(e, dict)]
    return '\n'.join(p for p in parts if isinstance(p, str))


def _parse_patch(patch):
    """(paths, added text) of an apply_patch body (*** Add File: / *** Update File: / *** Move to: lines)."""
    paths = re.findall(r'^\*\*\* (?:Add File|Update File|Delete File|Move to): *(.+?)\s*$', patch or '', re.M)
    added = '\n'.join(l[1:] for l in (patch or '').splitlines() if l.startswith('+') and not l.startswith('+++'))
    return paths, added


# ---- checks: each returns a reason string, or None ----

def check_prompt(text):
    kind = secret_in(text)
    if kind:
        return ('secret-guard: your message holds %s, so it was not sent. Set the secret outside the agent '
                '(your own terminal, or the environment-variables dialog) and refer to it by its variable name. '
                'Change the secret if it was ever sent before.' % kind)
    return None


def check_shell(cmd):
    if isinstance(cmd, (list, tuple)):
        cmd = ' '.join(str(c) for c in cmd)
    cmd = cmd if isinstance(cmd, str) else ''
    kind = secret_in(cmd)
    if kind:
        return ('secret-guard: the command holds %s. Read secrets from environment variables or git-ignored '
                'files inside the command; never put the value in it.' % kind)
    f = command_reads_secret_file(cmd)
    if f:
        return ('secret-guard: the command would print the secret file %s into the conversation. Use it from '
                'code without printing it, or print only its key names.' % f)
    return None


def check_read(paths, content=''):
    for p in paths:
        if secret_file(p):
            return 'secret-guard: %s is a secret file; its content must not enter the conversation.' % p
    kind = secret_in(content)
    if kind:
        return 'secret-guard: the file holds %s; its content must not enter the conversation.' % kind
    return None


def check_write(paths, text):
    reason = check_read(paths)
    if reason:
        return reason
    kind = secret_in(text)
    if kind:
        return ('secret-guard: the text to write holds %s. Write a placeholder and read the real value '
                'from the environment.' % kind)
    return None


def check_tool(tool, inp):
    """Reason to deny one tool call, for any agent's tool names."""
    if not isinstance(inp, dict):
        inp = {}
    if tool in PATCH_TOOLS:
        paths, added = _parse_patch(inp.get('command') or inp.get('patch') or inp.get('input') or '')
        return check_write(paths, added)
    if tool in SHELL_TOOLS:
        return check_shell(inp.get('command', ''))
    if tool in READ_TOOLS:
        return check_read(_paths(inp))
    if tool in WRITE_TOOLS:
        return check_write(_paths(inp), _text(inp))
    if tool.startswith('mcp'):
        return None
    # Unknown tool (for example a Copilot CLI file tool): check whatever fields it has.
    if 'command' in inp:
        return check_shell(inp.get('command'))
    return check_write(_paths(inp), _text(inp))


# ---- agent detection and replies ----

def detect_agent(data):
    event = data.get('hook_event_name') or ''
    if event in ('BeforeTool', 'BeforeAgent'):
        return 'gemini'
    if event in ('beforeShellExecution', 'beforeReadFile', 'beforeSubmitPrompt', 'beforeMCPExecution') or (
            event == 'preToolUse' and 'conversation_id' in data):
        return 'cursor'
    if 'toolName' in data or 'toolArgs' in data or ('sessionId' in data and not event):
        return 'copilot'
    if 'turn_id' in data or data.get('tool_name') in PATCH_TOOLS:
        return 'codex'
    return 'claude'


def _event(data, agent):
    """('prompt' | 'tool' | 'shell' | 'read' | None, event name) for one hook call."""
    event = data.get('hook_event_name') or ''
    if event in ('UserPromptSubmit', 'BeforeAgent', 'beforeSubmitPrompt', 'userPromptSubmitted'):
        return 'prompt', event
    if event in ('PreToolUse', 'BeforeTool', 'preToolUse'):
        return 'tool', event
    if event == 'beforeShellExecution':
        return 'shell', event
    if event == 'beforeReadFile':
        return 'read', event
    if agent == 'copilot' and not event:
        if 'toolName' in data:
            return 'tool', 'preToolUse'
        if 'prompt' in data:
            return 'prompt', 'userPromptSubmitted'
    return None, event


def _tool_input(data):
    if 'toolName' in data:
        args = data.get('toolArgs')
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {'command': args}
        return data.get('toolName') or '', args if isinstance(args, dict) else {}
    return data.get('tool_name') or '', data.get('tool_input') or {}


def reply(agent, kind, event, reason):
    """(exit code, stdout, stderr) in the block (or allow) format of the agent."""
    if agent == 'cursor':
        # Cursor blocks on invalid or missing JSON for permission hooks, so it always gets an answer.
        if kind == 'prompt':
            out = {'continue': True} if not reason else {'continue': False, 'user_message': reason}
        elif not reason:
            out = {'permission': 'allow'}
        else:
            out = {'permission': 'deny', 'user_message': reason}
            if kind != 'read':
                out['agent_message'] = reason
        return 0, json.dumps(out), ''
    if not reason:
        return 0, '', ''
    if agent == 'gemini':
        # decision "deny" on BeforeAgent discards the message; on BeforeTool the reason goes to the model.
        return 0, json.dumps({'decision': 'deny', 'reason': reason}), ''
    if agent == 'copilot':
        if kind == 'prompt':
            return 0, '', ''  # Copilot CLI drops the output of prompt hooks from config files.
        if event == 'PreToolUse':
            return 0, json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',
                                                         'permissionDecisionReason': reason}}), ''
        return 0, json.dumps({'permissionDecision': 'deny', 'permissionDecisionReason': reason}), ''
    # Claude Code and Codex share these shapes.
    if kind == 'prompt':
        return 2, '', reason + '\n'
    return 0, json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',
                                                 'permissionDecisionReason': reason}}), ''


def check(data, agent=None):
    """(exit code, stdout text, stderr text) for one hook call."""
    if not isinstance(data, dict):
        return 0, '', ''
    agent = agent or detect_agent(data)
    kind, event = _event(data, agent)
    if kind is None:
        return 0, '', ''
    if kind == 'prompt':
        reason = check_prompt(data.get('prompt', ''))
    elif kind == 'shell':
        reason = check_shell(data.get('command', ''))
    elif kind == 'read':
        reason = check_read([data.get('file_path', '')], data.get('content') or '')
    else:
        reason = check_tool(*_tool_input(data))
    return reply(agent, kind, event, reason)


def _agent_arg(argv):
    for i, a in enumerate(argv):
        value = a.split('=', 1)[1] if a.startswith('--agent=') else (
            argv[i + 1] if a == '--agent' and i + 1 < len(argv) else None)
        if value and value.lower() in AGENTS:
            return value.lower()
    return None


def main(argv=None):
    if _env('OFF') == '1':
        return 0
    agent = _agent_arg(sys.argv[1:] if argv is None else argv)
    try:
        data = json.loads(sys.stdin.buffer.read().decode('utf-8-sig', 'replace'))
    except Exception:
        return 0
    code, out, err = check(data, agent)
    if out:
        sys.stdout.write(out + '\n')
    if err:
        sys.stderr.write(err)
    return code


if __name__ == '__main__':
    sys.exit(main())
