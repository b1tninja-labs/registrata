# Agent notes

- Never use a tool name called `edit_file`; the only supported file editing tool is `editor`.
- After drafting an edit, double-check the tool name before sending the tool call.
- Prefer actual tool calls over describing intended tool calls.
- When applying small source edits, use `editor` with `path`, `old_text`, and `new_text`.
- Split oversized edits into multiple smaller `editor` calls instead of sending invalid or oversized tool payloads.
