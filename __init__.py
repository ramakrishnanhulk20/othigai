"""Othigai: a fire drill that shows whether your Hermes agent can be tricked, using fake bait."""

from .othigai.drill import SLICE_SECONDS, TOOL_SCHEMA, Drill, usable_slice_seconds


def register(ctx):
    # Read once at load on purpose. A model with a shell can edit config.yaml, but that edit does
    # nothing to this running process, so start files stay ignored on a normal install.
    drill = Drill(ctx, allow_script_start=ctx.get_config("allow_script_start", False) is True,
                  slice_seconds=usable_slice_seconds(ctx.get_config("slice_seconds", SLICE_SECONDS)))
    ctx.register_tool(name="othigai_run", toolset="othigai", schema=TOOL_SCHEMA, handler=drill.run_tool,
                      description=TOOL_SCHEMA["description"])
    ctx.register_command("drill", drill.on_drill_command, description="Arm or stop the Othigai fire drill.",
                         args_hint="[runs | stop]")
    ctx.register_hook("pre_tool_call", drill.on_pre_tool_call)
    ctx.register_hook("subagent_start", drill.on_subagent_start)
    ctx.register_hook("subagent_stop", drill.on_subagent_stop)
    ctx.register_hook("pre_api_request", drill.on_pre_api_request)
    ctx.register_hook("post_approval_response", drill.on_post_approval_response)
    ctx.register_hook("on_session_end", drill.on_session_end)
    ctx.register_hook("post_compaction", drill.on_post_compaction)
    # Last on purpose: unload runs in reverse order, so this comes before the gate hook is removed.
    ctx.on_unload(drill.on_unload)
