# Test: <one-line title of what this test verifies>

# NOTE: A spec does NOT declare a target. The project's single target is set once in the
# project's project.yaml (target: type/host/...); a "## Target" section here is a load error.

## Goal
# Plain English. Describe what the agent should accomplish in the focused window. The agent
# drives entirely by what it sees on screen (screenshots) and acts via mouse/keyboard.
Describe the end-to-end thing to accomplish in the target window.

## Setup
# OPTIONAL. Any preconditions or starting state the agent can assume (e.g. "the terminal
# opens at the home directory"). Delete this section if there's nothing to say.
Note any starting state the agent can rely on.

## Assertions
# A bullet list. Each item is evaluated independently and reported pass/fail with a
# screenshot as evidence. Keep each assertion concrete and observable on screen.
- The first observable condition that must hold.
- The second observable condition that must hold.
