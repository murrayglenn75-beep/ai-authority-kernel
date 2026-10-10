#!/usr/bin/env python3
from aak.agent_runtime import parse_prompt_tool_call

def verify():
    response = parse_prompt_tool_call('{"final":"ok"}')
    assert response.text == "ok"

if __name__ == "__main__":
    verify()
