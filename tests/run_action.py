#!/usr/bin/env python3
"""Run this composite action's steps the way the GitHub runner does, locally.

A composite action has no unit-test surface: the only thing that ever executes it is a real
workflow, so a mistake in an `if:` condition, a `${{ }}` expression or a shell quote is
invisible until it runs in somebody's pipeline. This resolves expressions and executes each
`run:` with the same shell the runner uses (`bash --noprofile --norc -eo pipefail`), with
RUNNER_TEMP and GITHUB_OUTPUT wired up.

It supports the expression subset this action actually uses — `inputs.*`,
`steps.<id>.outputs.*`, and `==` / `!=` against a literal. Anything else is an error rather
than a silent skip, so the harness cannot quietly stop testing a step.

  tests/run_action.py action.yml token=crv_… version=v1.0.0 api-url=http://localhost:8080
"""
import os
import re
import subprocess
import sys
import tempfile

import yaml

EXPR = re.compile(r"\$\{\{(.+?)\}\}")
COMPARISON = re.compile(r"^(?P<left>.+?)\s*(?P<op>==|!=)\s*(?P<right>.+?)$")


class Runner:
    def __init__(self, action: dict, inputs: dict[str, str]) -> None:
        self.action = action
        self.inputs = inputs
        self.step_outputs: dict[tuple[str, str], str] = {}

    def value(self, term: str) -> str:
        """A single operand: a quoted literal, an input, or a previous step's output."""
        term = term.strip()
        if len(term) >= 2 and term[0] == term[-1] and term[0] in "'\"":
            return term[1:-1]
        if term.startswith("inputs."):
            name = term.split(".", 1)[1]
            if name not in self.inputs:
                raise SystemExit(f"unknown input: {name}")
            return self.inputs[name]
        match = re.fullmatch(r"steps\.([\w-]+)\.outputs\.([\w-]+)", term)
        if match:
            return self.step_outputs.get((match.group(1), match.group(2)), "")
        raise SystemExit(f"unsupported expression term: {term!r}")

    def expression(self, expr: str) -> str:
        expr = expr.strip()
        comparison = COMPARISON.match(expr)
        if comparison and not expr.startswith(("inputs.", "steps.")) or (
            comparison and comparison.group("op")
        ):
            left = self.value(comparison.group("left"))
            right = self.value(comparison.group("right"))
            result = left == right if comparison.group("op") == "==" else left != right
            return "true" if result else "false"
        return self.value(expr)

    def interpolate(self, text: str) -> str:
        return EXPR.sub(lambda m: self.expression(m.group(1)), str(text))

    def run(self) -> int:
        runner_temp = tempfile.mkdtemp(prefix="runner-temp-")
        output_file = os.path.join(runner_temp, "github_output")

        for step in self.action["runs"]["steps"]:
            name = step["name"]
            if "if" in step and self.interpolate(step["if"]).strip() != "true":
                print(f"-- skip: {name}", flush=True)
                continue

            env = dict(os.environ, RUNNER_TEMP=runner_temp, GITHUB_OUTPUT=output_file)
            for key, raw in (step.get("env") or {}).items():
                env[key] = self.interpolate(raw)

            open(output_file, "w").close()
            print(f"-- step: {name}", flush=True)
            completed = subprocess.run(
                ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c",
                 self.interpolate(step["run"])],
                env=env,
            )
            for line in open(output_file):
                if "=" in line:
                    key, value = line.rstrip("\n").split("=", 1)
                    self.step_outputs[(step.get("id"), key)] = value
            if completed.returncode:
                print(f"-- failed: {name} (exit {completed.returncode})", flush=True)
                return completed.returncode
        return 0


def main() -> int:
    action = yaml.safe_load(open(sys.argv[1]))
    inputs = {name: str(spec.get("default", "")) for name, spec in action["inputs"].items()}
    for pair in sys.argv[2:]:
        key, value = pair.split("=", 1)
        if key not in inputs:
            raise SystemExit(f"unknown input: {key}")
        inputs[key] = value
    return Runner(action, inputs).run()


if __name__ == "__main__":
    sys.exit(main())
