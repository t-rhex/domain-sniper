import { test, expect, describe } from "bun:test";
import { bashCompletions, zshCompletions, fishCompletions } from "../src/completions.js";

describe("shell completions", () => {
  test("bash completions contain function definition", () => {
    const script = bashCompletions();
    expect(script).toContain("_domain_sniper");
    expect(script).toContain("complete");
    expect(script).toContain("domain-sniper");
  });

  test("zsh completions contain compdef", () => {
    const script = zshCompletions();
    expect(script).toContain("#compdef");
    expect(script).toContain("domain-sniper");
  });

  test("fish completions contain complete commands", () => {
    const script = fishCompletions();
    expect(script).toContain("complete -c domain-sniper");
  });
});
