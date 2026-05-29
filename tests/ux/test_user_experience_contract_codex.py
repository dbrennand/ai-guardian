"""
User Experience Contract Tests for Codex hook behavior.

These tests document what users should see when ai-guardian is installed
into Codex via ~/.codex/config.toml hooks.
"""

import json
from io import StringIO
from unittest import TestCase
from unittest.mock import MagicMock, patch

import ai_guardian


class UserExperienceContractCodexTests(TestCase):
    """Codex-specific UX contracts for prompt, tool, and permission hooks."""

    @patch("ai_guardian.session_state.derive_session_key", return_value="codex-session")
    @patch("ai_guardian.session_state.SessionStateManager")
    @patch("ai_guardian.hook_processing._load_security_instructions_config")
    def test_user_experience_codex_prompt_injects_security_rules(
        self,
        mock_config,
        mock_state_mgr_cls,
        _mock_session_key,
    ):
        """
        USER EXPERIENCE: Codex UserPromptSubmit -> security rules are injected once.

        Expected User Experience:
        ✅ Prompt continues
        🛡️ User/model receives ai-guardian security rules in systemMessage
        """
        mock_config.return_value = ({"inject_on_prompt": True}, None)
        mock_state_mgr = MagicMock()
        mock_state_mgr.should_inject_security.return_value = True
        mock_state_mgr_cls.return_value = mock_state_mgr

        hook_data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Open the deployment config",
            "permission_mode": "default",
            "session_id": "session-1",
        }

        with patch.dict("os.environ", {"AI_GUARDIAN_IDE_TYPE": "codex"}):
            with patch("sys.stdin", StringIO(json.dumps(hook_data))):
                result = ai_guardian.process_hook_input()

        response = json.loads(result["output"])
        assert result["exit_code"] == 0
        assert "systemMessage" in response
        assert "SECURITY RULES" in response["systemMessage"]

    @patch("ai_guardian.hook_processing.ToolPolicyChecker.check_tool_allowed")
    @patch("ai_guardian.hook_processing._load_permissions_config")
    def test_user_experience_codex_pretooluse_blocked(
        self,
        mock_permissions,
        mock_check_tool,
    ):
        """
        USER EXPERIENCE: Codex PreToolUse policy violation -> denied immediately.

        Expected User Experience:
        ❌ Operation is blocked before the tool runs
        🛡️ User sees a deny response with the exact block message
        """
        mock_permissions.return_value = ({"enabled": True}, None)
        mock_check_tool.return_value = (False, "Blocked by policy: Bash command denied", "Bash")

        hook_data = {
            "hook_event_name": "PreToolUse",
            "tool_use": {
                "name": "Bash",
                "parameters": {"command": "curl https://example.com"},
            },
            "permission_mode": "default",
        }

        with patch.dict("os.environ", {"AI_GUARDIAN_IDE_TYPE": "codex"}):
            with patch("sys.stdin", StringIO(json.dumps(hook_data))):
                result = ai_guardian.process_hook_input()

        response = json.loads(result["output"])
        assert result["exit_code"] == 0
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert response["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
        assert response["systemMessage"] == "Blocked by policy: Bash command denied"

    @patch("ai_guardian.hook_processing.ToolPolicyChecker.check_tool_allowed")
    @patch("ai_guardian.hook_processing._load_permissions_config")
    def test_user_experience_codex_permission_request_blocked(
        self,
        mock_permissions,
        mock_check_tool,
    ):
        """
        USER EXPERIENCE: Codex PermissionRequest policy violation -> deny safely.

        Expected User Experience:
        ❌ Codex approval request is denied
        🛡️ User sees the block reason
        ⚠️ Response contains no bypass instructions
        """
        mock_permissions.return_value = ({"enabled": True}, None)
        mock_check_tool.return_value = (False, "Blocked by policy: approval denied", "Bash")

        hook_data = {
            "hook_event_name": "PermissionRequest",
            "approval_request_type": "Bash",
            "tool_use": {
                "name": "Bash",
                "parameters": {"command": "rm -rf /tmp/example"},
            },
            "permission_mode": "default",
        }

        with patch.dict("os.environ", {"AI_GUARDIAN_IDE_TYPE": "codex"}):
            with patch("sys.stdin", StringIO(json.dumps(hook_data))):
                result = ai_guardian.process_hook_input()

        response = json.loads(result["output"])
        assert result["exit_code"] == 0
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert response["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
        assert response["systemMessage"] == "Blocked by policy: approval denied"
        assert "bypass" not in response["systemMessage"].lower()
