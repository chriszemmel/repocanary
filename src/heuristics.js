/**
 * The rule dispatcher: which checks one fetched file gets, and the checks
 * on the repository's own metadata.
 *
 * Everything the engine does is pure string analysis over text that
 * src/github.js already fetched. Nothing is executed, evaluated, or
 * installed. The rules themselves live by what they look at:
 *
 *   selection.js           which files a scan reads, and what they say runs
 *   signatures.js          the technique tables, high and medium
 *   code.js                behavioral rules over source and config bodies
 *   packagejson.js         lifecycle scripts and dependency fields
 *   agent-instructions.js  CLAUDE.md, AGENTS.md and rules files
 *   vendored.js            generated, bundled and test code, which steps down
 *   ecosystems.js          every other manifest, build file and autorun
 *   lockfile.js, obfuscation.js, typosquat.js
 *
 * Design note on false positives: the same raw patterns (eval, minification,
 * install scripts, crypto) appear in both malware and legitimate projects.
 * What separates them is WHERE the pattern lives and HOW SPECIFIC it is to
 * theft, which is why checkFile routes by path before any rule runs.
 */

import { AGENT_INSTRUCTION_FILES, CODE_EXT, CONFIG_FILE } from "./selection.js";
import {
  BLOB_SIGNALS,
  TEST_PATH,
  TEST_PATH_CAMEL,
  isGeneratedDocument,
  isQtTranslationCatalogue,
  isVendoredArtifact,
  maybeDowngrade,
} from "./vendored.js";
import { CI_PATH, checkCodeContent, checkNotebook, ownUrls } from "./code.js";
import {
  checkAgentHooks,
  checkBuildRs,
  checkComposerJson,
  checkDevcontainer,
  checkDirLocals,
  checkDockerCompose,
  checkDockerfile,
  checkEditorRc,
  checkEnvrc,
  checkGoFile,
  checkGradle,
  checkInstallHook,
  checkMakefile,
  checkMavenPom,
  checkMcpConfig,
  checkNpmrc,
  checkPyprojectToml,
  checkReadme,
  checkRequirementsTxt,
  checkRubyBuild,
  checkSetupPy,
  checkVscodeSettings,
  checkVscodeTasks,
  checkWorkflow,
  checkYarnrc,
  checkYarnrcClassic,
} from "./ecosystems.js";
import { checkAgentInstructions } from "./agent-instructions.js";
import { checkLockfile } from "./lockfile.js";
import { checkObfuscation } from "./obfuscation.js";
import { checkPackageJson } from "./packagejson.js";
import { lineOfIndex, redactSnippet } from "./textutil.js";

/**
 * Configuration an AI editor acts on by itself. An MCP server is started as
 * a local process when the folder is opened; agent hooks run commands while
 * the agent works. Neither needs an install step or a click.
 */
// Gemini CLI and Roo Code read a project's own MCP servers from these too,
// and the same server block was red in .mcp.json and green here.
const MCP_CONFIG = /(^|\/)(\.mcp\.json|\.vscode\/mcp\.json|\.cursor\/mcp\.json|\.zed\/settings\.json|\.gemini\/settings\.json|\.roo\/mcp\.json)$/;
const AGENT_HOOK_CONFIG = /(^|\/)(\.claude\/settings(\.local)?\.json|\.cursor\/hooks\.json)$/;
/** Per-directory editor configuration Neovim sources when it opens the folder. */
const EDITOR_RC = /(^|\/)(\.nvim\.lua|\.nvimrc|\.exrc)$/;

/** All content checks for one fetched file. */
export function checkFile(file, repo = null) {
  const { path, content, bytes, lines, executable = false } = file;
  const base = path.split("/").pop();
  const vendored = isVendoredArtifact(path, content);
  const findings = [];

  if (base === "package.json") findings.push(...checkPackageJson(path, content));
  findings.push(...checkLockfile(path, content));
  if (base === "setup.py") findings.push(...checkSetupPy(path, content));
  if (base === "pyproject.toml") findings.push(...checkPyprojectToml(path, content));
  if (/^requirements[\w.-]*\.txt$/.test(base)) findings.push(...checkRequirementsTxt(path, content));
  if (base === "build.rs") findings.push(...checkBuildRs(path, content));
  if (/\.go$/.test(base)) findings.push(...checkGoFile(path, content));
  if (/^(build|settings)\.gradle(\.kts)?$/.test(base)) findings.push(...checkGradle(path, content));
  if (base === "pom.xml") findings.push(...checkMavenPom(path, content));
  if (path.endsWith(".vscode/tasks.json") || path === ".vscode/tasks.json") {
    findings.push(...checkVscodeTasks(path, content));
  }
  // A .code-workspace file carries its own copies of the settings and tasks
  // blocks, so the same two traps travel in a file that is not under
  // .vscode/ at all and is opened directly rather than as a folder.
  if (/\.code-workspace$/.test(base)) {
    findings.push(...checkVscodeTasks(path, content), ...checkVscodeSettings(path, content));
  }
  if (MCP_CONFIG.test(path)) findings.push(...checkMcpConfig(path, content));
  if (AGENT_HOOK_CONFIG.test(path)) findings.push(...checkAgentHooks(path, content));
  if (base === ".dir-locals.el" || base === ".dir-locals-2.el") findings.push(...checkDirLocals(path, content));
  if (EDITOR_RC.test(path)) findings.push(...checkEditorRc(path, content));
  if (base === "devcontainer.json" || base === ".devcontainer.json") {
    findings.push(...checkDevcontainer(path, content));
  }
  if (base === "Makefile" || base === "makefile" || base === "GNUmakefile") {
    findings.push(...checkMakefile(path, content, ownUrls(repo)));
  }
  if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(path)) findings.push(...checkWorkflow(path, content));
  if (base === ".npmrc") findings.push(...checkNpmrc(path, content));
  if (base === "Dockerfile" || base === "dockerfile" || /\.dockerfile$/i.test(base)) {
    findings.push(...checkDockerfile(path, content, ownUrls(repo)));
  }
  if (base === ".pnpmfile.cjs") findings.push(...checkInstallHook(path, content));
  if (base === "composer.json") findings.push(...checkComposerJson(path, content));
  if (base === ".yarnrc.yml" || base === ".yarnrc.yaml") findings.push(...checkYarnrc(path, content));
  if (base === ".yarnrc") findings.push(...checkYarnrcClassic(path, content));
  if (path.endsWith(".vscode/settings.json") || path === ".vscode/settings.json") {
    findings.push(...checkVscodeSettings(path, content));
  }
  if (base === ".envrc") findings.push(...checkEnvrc(path, content));
  if (/^(docker-)?compose\.ya?ml$/.test(base)) findings.push(...checkDockerCompose(path, content, ownUrls(repo)));
  if (base === "extconf.rb" || base === "Rakefile" || base === "rakefile" || /\.gemspec$/.test(base)) {
    findings.push(...checkRubyBuild(path, content));
  }
  if (/^readme\.(md|txt|rst)$/i.test(path)) findings.push(...checkReadme(path, content));

  if (AGENT_INSTRUCTION_FILES.test(path)) findings.push(...checkAgentInstructions(path, content));

  if (/\.ipynb$/i.test(path)) findings.push(...checkNotebook(path, content, { bytes, lines }));

  // A file an install script or an editor hook actually runs is executable
  // by definition, so it is read as code even with no extension to go by.
  // "bin/lint" is where a dropper hides precisely because a name without a
  // suffix looks like tooling.
  if (isQtTranslationCatalogue(path, content)) {
    // Nothing here runs, and the marks the obfuscation rules look for are in
    // translated interface strings: a directional override a translator
    // pasted, a wallet filename named in a warning message. Read for hidden
    // text the way any file is, but not as code, so a translation is not an
    // accusation.
    findings.push(...checkObfuscation(path, content, { bytes, lines }));
  } else if (CODE_EXT.test(path) || CONFIG_FILE.test(path) || executable) {
    findings.push(...checkCodeContent(path, content, { bytes, lines }, undefined, repo, executable));
  } else if (AGENT_INSTRUCTION_FILES.test(path)) {
    // Prose, not code. An instruction file is read for what is hidden in it,
    // the way any file is, but not for the behaviour rules: a contributor
    // guide saying "never hardcode paths like ~/.config/gcloud/" is telling
    // people not to do the thing those rules look for, and
    // google-cloud-python turned red for exactly that sentence.
    findings.push(...checkObfuscation(path, content, { bytes, lines }));
  }

  let downgraded = maybeDowngrade(findings, vendored);
  // Rust keeps a crate's unit tests in the same file as the code they test,
  // under `#[cfg(test)] mod tests`, so no path rule can ever see them. That
  // made every Rust project's test suite read as production code:
  // yologdev/yoyo-evolve is a tool that blocks dangerous shell commands, and
  // it turned red because its tests assert that it catches writing to
  // ~/.ssh/authorized_keys. By convention the module sits at the end of the
  // file, so a finding below the attribute is in it. Same downgrade as a
  // test path, and for the same reason: this code does not run when the
  // project is installed or opened.
  const rustTests = /\.rs$/i.test(path) ? content.indexOf("#[cfg(test)]") : -1;
  const rustTestLine = rustTests >= 0 ? lineOfIndex(content, rustTests) : Infinity;
  if (rustTestLine !== Infinity) {
    downgraded = downgraded.map((f) =>
      f.severity === "high" && typeof f.line === "number" && f.line >= rustTestLine
        ? {
            ...f,
            severity: "medium",
            why: `${f.why} (This is inside the file's #[cfg(test)] module, which is compiled only when the crate's tests run, so it is reported as a caution rather than as danger.)`,
          }
        : f,
    );
  }
  // A generated documentation page is prose, and prose about a tool names
  // the commands that tool runs. rclone ships a 3.7 MB pandoc build of its
  // user manual at MANUAL.html, and it turned red for the sentence telling a
  // reader to "systemctl enable docker-volume-rclone.service". That is the
  // same reasoning the instruction-file carve-out already uses: a document
  // describing a command is not a document running one.
  //
  // One step down and no more, like a forged licence banner, because a
  // generator stamp is cheap to write. The document still has to be shaped
  // like machine output, and the obfuscation rules still read it at full
  // weight, so hidden text in a "manual" is caught either way.
  if (isGeneratedDocument(path, content)) {
    downgraded = downgraded.map((f) =>
      f.severity === "high"
        ? {
            ...f,
            severity: "medium",
            why: `${f.why} (This is inside a generated documentation page, where a command appears because the page describes it rather than because the page runs it, so it is reported as a caution rather than as danger.)`,
          }
        : f,
    );
  }
  // A directional override or an invisible character inside a translated UI
  // string is the translator's, not a Trojan Source attack: a translation
  // catalogue is data Qt renders, never code it runs. Reported as
  // informational rather than convicting, because the marks are still worth a
  // glance, and never silenced. bitcoin's Filipino locale carried a
  // Left-to-Right Override in a passphrase warning.
  if (isQtTranslationCatalogue(path, content)) {
    const TRANSLATION_NOISE = new Set(["bidi-override", "invisible-characters", "private-use-steganography", "homoglyph-identifier", "homoglyph-url"]);
    downgraded = downgraded.map((f) =>
      TRANSLATION_NOISE.has(f.id)
        ? {
            ...f,
            severity: "low",
            why: `${f.why} (This is inside a Qt translation catalogue, where such a character sits in translated interface text rather than in code, so it is reported as informational.)`,
          }
        : f,
    );
  }
  // The same reasoning as the test-path block below, for the other place a
  // project keeps code that is not the code you run. A build agent, a release
  // runner or a container the project provisions is not the machine of the
  // person who cloned the repository, and that machine is the only one this
  // tool is asked about. apache/airflow generating a host key for its own test
  // container, ponyc writing a generated key to a BSD build VM, and calico
  // fetching a script into a CI epilogue are all the real thing done to
  // infrastructure the project owns.
  //
  // One step and no more, and `!executable` still holds: a conviction here
  // becomes a caution rather than vanishing, so a payload parked in .github/
  // is still reported, and a file an install script or an editor hook starts
  // is judged as one wherever it sits.
  // A CI configuration file is excluded: it is not a script the runner
  // invokes, it is the declaration of what the runner does, and a workflow
  // that posts ${{ secrets.NPM_TOKEN }} to a stranger is the declaration
  // itself. One of the malicious benchmark samples is exactly that, and it stops
  // being red the moment this block reads the file it is written in.
  const CI_CONFIG_FILE = /\.ya?ml$|(^|\/)(Jenkinsfile|Makefile)$/i;
  // Not where the test-path block below will also fire. Both say "one step
  // and no more", and ci/test/x.sh matches both: stacked, a conviction there
  // became a note. The test-path block is the more specific of the two and
  // is left to do the work.
  const alsoTestPath = TEST_PATH.test(path) || TEST_PATH_CAMEL.test(path);
  if (CI_PATH.test(path) && !CI_CONFIG_FILE.test(path) && !alsoTestPath && !executable) {
    downgraded = downgraded.map((f) =>
      f.severity === "high"
        ? {
            ...f,
            severity: "medium",
            why: `${f.why} (This is in a directory that holds the project's own build and CI scripts, which run on a build agent rather than on your machine when you clone or install, so it is reported as a caution rather than as danger.)`,
          }
        : f,
    );
  }
  // `!executable` is the condition the downgrade's own reasoning states. A
  // file an install script or an editor hook names does run when the project
  // is installed or opened, whatever directory it sits in, so moving a
  // working payload from src/ to examples/ must not buy a step: the same C2
  // fingerprint and the same wallet read went from red to a caution on that
  // rename alone, while npm still ran the file.
  if ((TEST_PATH.test(path) || TEST_PATH_CAMEL.test(path)) && !executable) {
    // Tagged as well as downgraded. This block's own reasoning is that a
    // finding here "cannot be the sole evidence of danger"; the tag is what
    // lets verdict.js say the same thing about three of them, which are one
    // observation about the test suite rather than three about the project.
    downgraded = downgraded.map((f) => ({ ...f, testPath: true })).map((f) => {
      if (f.severity === "high") {
        return {
          ...f,
          severity: "medium",
          why: `${f.why} (This is in a test path, which does not run when the project is installed or opened, so it is reported as a caution rather than as danger.)`,
        };
      }
      // Encoded fixtures (contract bytecode, mock responses, generated
      // cases) are what test data looks like; a blob there is informational,
      // and a loader that decodes it is caught by its own rule.
      if (f.severity === "medium" && BLOB_SIGNALS.has(f.id)) {
        return {
          ...f,
          severity: "low",
          why: `${f.why} (This is test data, where encoded fixtures are normal, so it is treated as informational.)`,
        };
      }
      // Any remaining caution in a test path is informational. Test code is
      // not what runs when the project is installed or opened, and a test
      // reproducing the shape it tests for is the normal case: babel-generator
      // keeps a 1 MB minified page under test/fixtures to exercise its
      // printer and earned a caution twice, once for the input and once for
      // the expected output; pnpm's crates/config/src/tests.rs asserts what
      // its config reader does with a credential path.
      //
      // The step down is one step, from a caution to a note, and the
      // !executable guard above still holds: a file an install script or an
      // editor hook names is judged as one wherever it sits. A conviction in
      // a test path has already become a caution higher up rather than
      // vanishing here.
      if (f.severity === "medium") {
        return {
          ...f,
          severity: "low",
          why: `${f.why} (This is a test path, which does not run when the project is installed or opened, so it is treated as informational.)`,
        };
      }
      return f;
    });
  }

  // A payload hiding in a build config file (never a vendored artifact) is
  // worth an explicit extra nudge: it is the classic hiding spot.
  if (CONFIG_FILE.test(path) && !vendored && downgraded.some((f) => f.severity === "high")) {
    downgraded.push({
      id: "payload-in-config",
      severity: "high",
      file: path,
      line: null,
      snippet: path,
      why: "The suspicious code above lives inside a build config file (like next.config.js or postcss.config.js), a spot reviewers rarely open, and exactly where fake-interview malware hides.",
      next: "Do not run or build this project.",
    });
  }

  return downgraded;
}

/**
 * Context signals: repo and account facts that raise suspicion but can each
 * be innocent. By design they are yellow only, never red on their own, so
 * every severity in here is medium or low. A test enforces that.
 */
export function checkRepoMeta(meta, now = Date.now()) {
  const findings = [];
  const days = (iso) => (iso ? Math.floor((now - new Date(iso).getTime()) / 86_400_000) : null);

  // 90 days: throwaway accounts in these campaigns are reported and replaced
  // long before that, and a real developer's account is almost never younger.
  const accountAge = days(meta.ownerCreatedAt);
  if (accountAge !== null && accountAge >= 0 && accountAge < 90) {
    findings.push({
      id: "new-account",
      severity: "medium",
      file: "(repository)",
      line: null,
      snippet: `Account created ${accountAge} day${accountAge === 1 ? "" : "s"} ago`,
      why: "The GitHub account that owns this repo is brand new. Scam accounts are created fresh and thrown away after being reported.",
      next: "Check the account's other activity and whether the company it claims to represent actually exists.",
    });
  }

  if (meta.ownerPublicRepos !== null && meta.ownerPublicRepos !== undefined && meta.ownerPublicRepos <= 2) {
    findings.push({
      id: "single-repo-account",
      severity: "low",
      file: "(repository)",
      line: null,
      snippet: `Owner has ${meta.ownerPublicRepos} public repo(s)`,
      why: "The owner has almost no other public work. Real companies and developers usually have a footprint.",
      next: "Search for the company or person elsewhere and see if this account matches.",
    });
  }

  if (meta.ownerType === "Organization" && meta.orgPublicMembers === 0) {
    // Membership is opt-in on GitHub, so most honest organisations show zero
    // public members. A shell organisation is one with nothing else in it:
    // zero members and only a handful of repositories.
    const shell = meta.ownerPublicRepos !== null && meta.ownerPublicRepos !== undefined && meta.ownerPublicRepos <= 3;
    findings.push({
      id: "empty-org",
      severity: shell ? "medium" : "low",
      file: "(repository)",
      line: null,
      snippet: "Organization has no public members",
      why: "This 'company' organization has zero visible members, a common trait of fake recruiter orgs set up to look legitimate.",
      next: "Ask the recruiter for the names of engineers at the company and check they exist.",
    });
  }

  if (meta.isFork) {
    findings.push({
      id: "repo-is-fork",
      severity: "low",
      file: "(repository)",
      line: null,
      snippet: "Repository is a fork",
      why: "This repo is a fork of another project. Scammers often fork a legitimate project and add a payload, so the code looks real because most of it is.",
      next: "Compare this fork against its upstream and read every commit the fork added.",
    });
  }

  // Ten or more of the recent commits inside one day: enough to rule out a
  // quiet week of real work, few enough to catch a repository assembled in an
  // afternoon.
  const dates = (meta.commitDates ?? []).map((d) => new Date(d).getTime()).filter((t) => !Number.isNaN(t));
  if (dates.length >= 10 && Math.max(...dates) - Math.min(...dates) <= 86_400_000) {
    findings.push({
      id: "commit-burst",
      severity: "low",
      file: "(repository)",
      line: null,
      snippet: `${dates.length} recent commits within a single day`,
      why: "The repo's recent history was created in a single burst. Real projects accumulate history; staged ones are assembled in an afternoon.",
      next: "Check whether the commit dates and messages look like a project actually being developed.",
    });
  }

  const uniqueAuthors = new Set(meta.commitAuthorNames ?? []);
  if (meta.ownerType === "User" && uniqueAuthors.size > 0) {
    const owner = meta.owner.toLowerCase();
    const anyMatch = [...uniqueAuthors].some(
      (n) => n.toLowerCase().includes(owner) || owner.includes(n.toLowerCase().replace(/\s+/g, "")),
    );
    if (!anyMatch) {
      findings.push({
        id: "author-mismatch",
        severity: "low",
        file: "(repository)",
        line: null,
        snippet: `Commits by: ${[...uniqueAuthors].slice(0, 3).join(", ")}`,
        why: "The names on the commits do not match the account that owns the repo, consistent with code that was copied or planted rather than written here.",
        next: "Check who actually wrote this code and why it lives under this account.",
      });
    }
  }

  const themeText = `${meta.repo} ${meta.description ?? ""} ${(meta.topics ?? []).join(" ")}`.toLowerCase();
  if (/crypto|defi|web3|blockchain|wallet|trading|exchange|nft|fintech|\bai\b|bot\b/.test(themeText)) {
    findings.push({
      id: "lure-theme",
      severity: "low",
      file: "(repository)",
      line: null,
      snippet: redactSnippet(meta.description ?? meta.repo, 120),
      why: "The repo is themed around crypto, DeFi, AI, or fintech, the favorite lure topics of fake-interview scams. Not damning alone, but it raises the bar for the other signals.",
      next: "Apply extra suspicion to everything else about this repo and the person who sent it.",
    });
  }

  return findings;
}
