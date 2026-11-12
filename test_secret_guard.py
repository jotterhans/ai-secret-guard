import json
import unittest

from secret_guard import _agent_arg, check, secret_file, secret_in

# Built from parts so this file does not itself look like a secret to scanners.
PG = 'postgresql://app_user:' + 'Real' + 'Pass123' + '@db.example.com:5432/app'
ANT = 'sk-ant-' + 'api03-' + 'a' * 40


def prompt(text):
    return check({'hook_event_name': 'UserPromptSubmit', 'prompt': text})


def tool(name, **inp):
    code, out, _ = check({'hook_event_name': 'PreToolUse', 'tool_name': name, 'tool_input': inp})
    return json.loads(out)['hookSpecificOutput']['permissionDecision'] if out else 'allow'


class PromptTest(unittest.TestCase):
    def test_blocks_a_prompt_with_a_db_url(self):
        code, _, err = prompt('set MY_DB_URL to ' + PG)
        self.assertEqual(code, 2)
        self.assertIn('a URL with a password', err)
        self.assertNotIn('RealPass123', err)

    def test_blocks_api_keys_and_password_variables(self):
        self.assertEqual(prompt('key ' + ANT)[0], 2)
        self.assertEqual(prompt('$env:PGPASSWORD="' + 'Hunter2' + 'Long"')[0], 2)
        self.assertEqual(prompt('Server=x;Password=' + 'Abc' + '12345;')[0], 2)

    def test_lets_placeholders_and_plain_text_through(self):
        for text in ('postgresql://user:<password>@host/db', 'postgresql://u:pw@h/db', 'PASSWORD=${DB_PASS}',
                     'the password must be rotated', 'see .env.example', '"password": "changeme"'):
            self.assertEqual(prompt(text)[0], 0, text)


class ToolTest(unittest.TestCase):
    def test_denies_reading_secret_files(self):
        self.assertEqual(tool('Read', file_path=r'C:\repo\engine\secrets.local.json'), 'deny')
        self.assertEqual(tool('Read', file_path='/home/u/.ssh/config'), 'deny')
        self.assertEqual(tool('Read', file_path='/repo/.env'), 'deny')
        self.assertEqual(tool('Read', file_path='/repo/.env.example'), 'allow')
        self.assertEqual(tool('Read', file_path='/home/u/.ssh/id_ed25519.pub'), 'allow')

    def test_denies_commands_that_hold_or_print_secrets(self):
        self.assertEqual(tool('Bash', command='psql "' + PG + '" -c "select 1"'), 'deny')
        self.assertEqual(tool('Bash', command='cat engine/secrets.local.json'), 'deny')
        self.assertEqual(tool('PowerShell', command='Get-Content .env'), 'deny')
        self.assertEqual(tool('Bash', command='git status --short'), 'allow')
        self.assertEqual(tool('Bash', command='python -c "import os; print(bool(os.environ.get(\'DB_URL\')))"'), 'allow')

    def test_denies_writing_a_real_secret(self):
        self.assertEqual(tool('Write', file_path='/repo/config.py', content='URL = "' + PG + '"'), 'deny')
        self.assertEqual(tool('Write', file_path='/repo/config.py', content='URL = os.environ["DB_URL"]'), 'allow')


class CodexTest(unittest.TestCase):
    """Input and output shapes from https://developers.openai.com/codex/hooks"""

    def call(self, event, **fields):
        data = {'session_id': 's', 'turn_id': 't', 'cwd': '/repo', 'hook_event_name': event, 'model': 'm',
                'permission_mode': 'default'}
        data.update(fields)
        return check(data)

    def test_blocks_a_prompt_with_exit_2(self):
        code, out, err = self.call('UserPromptSubmit', prompt='use ' + PG)
        self.assertEqual((code, out), (2, ''))
        self.assertIn('a URL with a password', err)
        self.assertEqual(self.call('UserPromptSubmit', prompt='hello')[0], 0)

    def test_denies_bash_with_permission_decision(self):
        code, out, _ = self.call('PreToolUse', tool_name='Bash', tool_use_id='u', tool_input={'command': 'cat .env'})
        self.assertEqual(json.loads(out)['hookSpecificOutput']['permissionDecision'], 'deny')
        self.assertEqual(self.call('PreToolUse', tool_name='Bash', tool_input={'command': 'ls'})[1], '')

    def test_checks_apply_patch(self):
        patch = '*** Begin Patch\n*** Add File: app/config.py\n+URL = "%s"\n*** End Patch\n' % PG
        self.assertIn('deny', self.call('PreToolUse', tool_name='apply_patch', tool_input={'command': patch})[1])
        patch = '*** Begin Patch\n*** Update File: deploy/.env\n@@\n+DEBUG=1\n*** End Patch\n'
        self.assertIn('deny', self.call('PreToolUse', tool_name='apply_patch', tool_input={'command': patch})[1])
        patch = '*** Begin Patch\n*** Add File: app/config.py\n+URL = os.environ["DB_URL"]\n*** End Patch\n'
        self.assertEqual(self.call('PreToolUse', tool_name='apply_patch', tool_input={'command': patch})[1], '')


class GeminiTest(unittest.TestCase):
    """Input and output shapes from https://geminicli.com/docs/hooks/reference/"""

    def call(self, event, **fields):
        data = {'session_id': 's', 'transcript_path': '/t', 'cwd': '/repo', 'hook_event_name': event,
                'timestamp': '2026-01-01T00:00:00Z'}
        data.update(fields)
        code, out, _ = check(data)
        self.assertEqual(code, 0)
        return json.loads(out) if out else {}

    def tool(self, name, **inp):
        return self.call('BeforeTool', tool_name=name, tool_input=inp).get('decision', 'allow')

    def test_denies_a_prompt(self):
        out = self.call('BeforeAgent', prompt='key ' + ANT)
        self.assertEqual(out['decision'], 'deny')
        self.assertNotIn(ANT, out['reason'])
        self.assertEqual(self.call('BeforeAgent', prompt='hello'), {})

    def test_denies_gemini_tools(self):
        self.assertEqual(self.tool('read_file', file_path='~/.ssh/id_rsa'), 'deny')
        self.assertEqual(self.tool('read_file', file_path='C:\\repo\\.env'), 'deny')
        self.assertEqual(self.tool('read_file', file_path='/repo/.env.example'), 'allow')
        self.assertEqual(self.tool('read_many_files', include=['src/**', '.env']), 'deny')
        self.assertEqual(self.tool('run_shell_command', command='type secrets.local.json'), 'deny')
        self.assertEqual(self.tool('run_shell_command', command='git status'), 'allow')
        self.assertEqual(self.tool('write_file', file_path='a.py', content='URL = "' + PG + '"'), 'deny')
        self.assertEqual(self.tool('replace', file_path='a.py', old_string='x', new_string='y'), 'allow')


class CursorTest(unittest.TestCase):
    """Input and output shapes from https://cursor.com/docs/agent/hooks"""

    def call(self, event, **fields):
        data = {'conversation_id': 'c', 'generation_id': 'g', 'hook_event_name': event, 'workspace_roots': ['/r']}
        data.update(fields)
        code, out, _ = check(data)
        self.assertEqual(code, 0)
        return json.loads(out)

    def test_always_answers(self):
        self.assertEqual(self.call('beforeShellExecution', command='ls', cwd='/r'), {'permission': 'allow'})
        self.assertEqual(self.call('beforeSubmitPrompt', prompt='hi'), {'continue': True})

    def test_blocks(self):
        self.assertEqual(self.call('beforeShellExecution', command='cat .env')['permission'], 'deny')
        self.assertEqual(self.call('beforeReadFile', file_path='/r/.env', content='A=1')['permission'], 'deny')
        self.assertEqual(self.call('beforeReadFile', file_path='/r/a.py', content='u = "' + PG + '"')['permission'],
                         'deny')
        self.assertEqual(self.call('beforeReadFile', file_path='/r/a.py', content='x = 1')['permission'], 'allow')
        self.assertIs(self.call('beforeSubmitPrompt', prompt=PG)['continue'], False)


class CopilotTest(unittest.TestCase):
    """Input and output shapes from https://docs.github.com/en/copilot/reference/hooks-configuration"""

    def tool(self, name, args):
        code, out, _ = check({'sessionId': 's', 'timestamp': 1704614400000, 'cwd': '/tmp', 'toolName': name,
                              'toolArgs': json.dumps(args)})
        return json.loads(out)['permissionDecision'] if out else 'allow'

    def test_denies_shell(self):
        self.assertEqual(self.tool('bash', {'command': 'cat ~/.aws/config'}), 'deny')
        self.assertEqual(self.tool('bash', {'command': 'ls'}), 'allow')

    def test_prompt_hook_cannot_block(self):
        self.assertEqual(check({'sessionId': 's', 'timestamp': 1, 'cwd': '/', 'prompt': PG}), (0, '', ''))


class AgentArgTest(unittest.TestCase):
    def test_agent_argument_overrides_detection(self):
        data = {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash', 'tool_input': {'command': 'cat .env'}}
        self.assertIn('permissionDecision', check(data, 'claude')[1])
        self.assertEqual(_agent_arg(['--agent', 'gemini']), 'gemini')
        self.assertEqual(_agent_arg(['--agent=codex']), 'codex')
        self.assertIsNone(_agent_arg([]))


class HelpersTest(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(secret_in('-----BEGIN OPENSSH PRIVATE KEY-----'), 'a private key')
        self.assertIsNone(secret_in('nothing here'))
        self.assertTrue(secret_file('tenants/secrets.json'))
        self.assertFalse(secret_file('README.md'))


if __name__ == '__main__':
    unittest.main()
