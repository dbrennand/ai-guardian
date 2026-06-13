"""OpenAI Codex hook adapter.

Codex uses Claude-compatible PascalCase hook payloads and JSON responses
for the shared events, but it also adds a PermissionRequest hook and
stores transcripts in ~/.codex/sessions/YYYY/MM/DD/*.jsonl.
"""

import glob
import json
import os
from typing import ClassVar, Dict, List

from ai_guardian.constants import HookEvent
from ai_guardian.hook_adapters.claude_code import ClaudeCodeAdapter


class CodexAdapter(ClaudeCodeAdapter):
    """Adapter for OpenAI Codex.

    Codex shares Claude Code's hook format (PascalCase events, same
    JSON response structure), but it adds PermissionRequest-specific
    behavior and transcript path discovery.
    """

    ENV_ALIASES: ClassVar[List[str]] = ["codex"]

    # Base directory for Codex session transcripts
    SESSIONS_DIR = os.path.expanduser("~/.codex/sessions")

    @property
    def ide_type(self):
        from ai_guardian.response_format import IDEType
        return IDEType.CODEX

    @property
    def name(self) -> str:
        return "OpenAI Codex"

    @classmethod
    def can_handle(cls, hook_data: Dict) -> bool:
        event_name = hook_data.get("hook_event_name")
        return bool(
            event_name == "PermissionRequest"
            or "approval_request_type" in hook_data
            or "permission_mode" in hook_data
        )

    def normalize_input(self, hook_data: Dict):
        normalized = super().normalize_input(hook_data)

        approval_request_type = hook_data.get("approval_request_type")
        if approval_request_type and not normalized.tool_name:
            normalized.tool_name = approval_request_type

        if normalized.event == HookEvent.PERMISSION_REQUEST:
            if not normalized.tool_input:
                if isinstance(hook_data.get("tool_input"), dict):
                    normalized.tool_input = hook_data["tool_input"]
                elif isinstance(hook_data.get("input"), dict):
                    normalized.tool_input = hook_data["input"]
                elif isinstance(hook_data.get("parameters"), dict):
                    normalized.tool_input = hook_data["parameters"]
                elif isinstance(hook_data.get("approval_request"), dict):
                    normalized.tool_input = hook_data["approval_request"]

            if normalized.tool_name == "Bash":
                command = hook_data.get("command")
                if isinstance(command, str) and command and "command" not in normalized.tool_input:
                    normalized.tool_input["command"] = command

        return normalized

    def format_response(
        self,
        has_secrets: bool,
        error_message=None,
        hook_event: HookEvent = HookEvent.PROMPT,
        warning_message=None,
        modified_output=None,
        violation_type=None,
        security_message=None,
    ) -> Dict:
        if hook_event != HookEvent.PERMISSION_REQUEST:
            return super().format_response(
                has_secrets=has_secrets,
                error_message=error_message,
                hook_event=hook_event,
                warning_message=warning_message,
                modified_output=modified_output,
                violation_type=violation_type,
                security_message=security_message,
            )

        final_error = self._combine_error_messages(error_message, warning_message) if has_secrets else None
        if has_secrets and final_error:
            response = {
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {
                        "behavior": "deny",
                        "message": final_error,
                    },
                },
                "systemMessage": final_error,
            }
        else:
            # Let Codex continue with its native approval flow.
            response = {}

        return self._add_metadata(
            {"output": json.dumps(response), "exit_code": 0},
            has_secrets,
            violation_type,
        )

    def get_default_transcript_paths(self) -> List[str]:
        """Return Codex JSONL transcript paths that exist on disk.

        Codex organises sessions by date: ~/.codex/sessions/YYYY/MM/DD/*.jsonl
        Returns all JSONL files sorted by modification time (most recent first)
        so the caller can scan the active session.
        """
        if not os.path.isdir(self.SESSIONS_DIR):
            return []

        pattern = os.path.join(self.SESSIONS_DIR, "**", "*.jsonl")
        files = glob.glob(pattern, recursive=True)
        if not files:
            return []

        # Sort by modification time, most recent first
        files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
        return files
