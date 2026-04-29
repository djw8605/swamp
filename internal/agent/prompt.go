package agent

import (
	"fmt"
	"strings"

	"github.com/bbockelm/swamp/internal/models"
)

var phase1Template = `You are a security analyst performing a comprehensive vulnerability assessment.

## Target Repository
- Repository: %s
- Branch: %s
%s

## Custom Instructions
%s
%s
## Your Task
1. %s
2. Immediately after %s, record the exact commit SHA being analyzed:
   Run ` + "`git rev-parse HEAD`" + ` from inside the %s directory
   and write the full 40-character SHA to ` + "`output/git_sha.txt`" + ` (just the SHA, no newline or extra text).
3. Identify security vulnerabilities across the following categories:
   - OWASP Top 10
   - CWE categories (buffer overflows, race conditions, path traversal, command injection, etc.)
   - Dependency vulnerabilities (outdated packages, known CVEs)
   - Secrets in code (API keys, passwords, tokens, private keys)
   - Authentication and authorization issues
   - Cryptographic weaknesses
4. For each vulnerability found, provide:
   - Severity level (critical, high, medium, low, informational)
   - CWE identifier if applicable
   - Exact file location (file path + line number)
   - Description of the vulnerability
   - Recommended fix
5. Output your findings in three formats:
   a. A SARIF file at ` + "`output/results.sarif`" + ` following the SARIF 2.1.0 specification
   b. A Markdown summary at ` + "`output/report.md`" + ` with an executive summary, findings table, and detailed descriptions
   c. An analyst notes file at ` + "`output/notes.md`" + ` (see below)

## Analyst Notes (output/notes.md)
Write concise notes about this project that would help a future security analyst reviewing this codebase.
Include:
- Key architectural observations (frameworks, auth patterns, data flow)
- Areas of the code that deserve deeper review in future runs
- Any suspicious patterns that weren't conclusive enough to report as findings
- Notes about the build system, dependencies, or deployment model that affect security posture
- What you focused on and what you did NOT have time to review

Keep it under 2000 words. These notes will be provided to future analysis runs for continuity.

Be thorough but precise. Only report genuine vulnerabilities in the SARIF/report, not style issues or theoretical concerns.
Focus on finding NEW and DIFFERENT issues not already listed in the prior findings below.

## Error Reporting
If you are unable to complete the analysis (e.g. cannot access the repository, missing dependencies,
build failures, or any other blocker), write a concise explanation (under 30 words) to ` + "`output/error.txt`" + `
and stop. Do NOT fabricate findings.`

var phase2Template = `You are a security researcher validating previously identified vulnerabilities.

## Context
Review the SARIF findings at output/results.sarif and the report at output/report.md.

## Your Task
1. For each HIGH and CRITICAL severity finding in the SARIF file:
   a. Determine if the vulnerability is exploitable in practice
   b. Write a minimal proof-of-concept exploit demonstrating the vulnerability
   c. Place POC files in output/exploits/ (named by finding ID)
   d. Document the exploitation steps
2. Update output/report.md:
   - Mark findings as CONFIRMED (exploit works), LIKELY (reasonable but not demonstrated), or UNCONFIRMED (could not reproduce)
   - For each validated finding, describe the POC and impact
   - Add an "Exploit Validation" section
3. Update output/results.sarif:
   - Add properties to each result indicating validation status

Only attempt safe, non-destructive proof-of-concept exploits.
Do NOT attempt exploits against external systems.
This analysis is for defensive purposes only.`

// formatAnalysisContext builds the "Prior Analysis Context" prompt section
// from open findings, user annotations, and notes from recent runs.
func formatAnalysisContext(ac *models.AnalysisContext) string {
	if ac == nil {
		return ""
	}

	var sb strings.Builder

	// Prior notes from recent runs.
	if len(ac.PriorNotes) > 0 {
		sb.WriteString("\n## Analyst Notes from Prior Runs\n")
		sb.WriteString("The following notes were written by the analyst in previous runs of this project. ")
		sb.WriteString("Use them to build on prior work and avoid re-treading the same ground.\n\n")
		for i, note := range ac.PriorNotes {
			fmt.Fprintf(&sb, "### Run %d (most recent first)\n", i+1)
			// Truncate very long notes to avoid blowing up the context window.
			if len(note) > 4000 {
				note = note[:4000] + "\n... (truncated)"
			}
			sb.WriteString(note)
			sb.WriteString("\n\n")
		}
	}

	// Open findings from prior analyses.
	if len(ac.OpenFindings) > 0 {
		sb.WriteString("\n## Known Open Findings (from prior analyses)\n")
		sb.WriteString("These vulnerabilities have already been identified. Do NOT re-report them unless you have ")
		sb.WriteString("significant new information. Instead, focus your effort on finding NEW vulnerabilities.\n\n")
		sb.WriteString("| Severity | Rule | File:Line | Status | Message |\n")
		sb.WriteString("|----------|------|-----------|--------|---------|\n")
		for _, f := range ac.OpenFindings {
			level := f.Level
			switch level {
			case "error":
				level = "HIGH"
			case "warning":
				level = "MEDIUM"
			case "note":
				level = "LOW"
			}
			loc := f.FilePath
			if f.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", f.FilePath, f.StartLine)
			}
			msg := f.Message
			if len(msg) > 120 {
				msg = msg[:120] + "…"
			}
			annotation := f.Status
			if f.Note != "" {
				annotation += " — " + f.Note
			}
			fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s |\n", level, f.RuleID, loc, annotation, msg)
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// BuildPrompt constructs the analysis prompt for a given phase.
// If preClonedPath is non-empty, the prompt tells the agent the repo is
// already available locally instead of asking it to clone (so no credentials
// are ever included in the prompt).
func BuildPrompt(pkg *models.SoftwarePackage, phase string, analysisPrompt string, analysisCtx *models.AnalysisContext, preClonedPath string) string {
	commitLine := ""
	if pkg.GitCommit != "" {
		commitLine = fmt.Sprintf("- Commit: %s", pkg.GitCommit)
	}

	customPrompt := strings.TrimSpace(pkg.AnalysisPrompt)
	if ap := strings.TrimSpace(analysisPrompt); ap != "" {
		if customPrompt != "" {
			customPrompt += "\n\n" + ap
		} else {
			customPrompt = ap
		}
	}
	if customPrompt == "" {
		customPrompt = "No additional instructions."
	}

	switch phase {
	case "phase2":
		return phase2Template
	default:
		contextSection := formatAnalysisContext(analysisCtx)

		// Determine clone vs pre-cloned instructions.
		var step1, afterVerb, dirRef string
		if preClonedPath != "" {
			step1 = fmt.Sprintf("The repository has already been cloned for you at `%s`. Do NOT run git clone. Thoroughly review the codebase from that existing directory.", preClonedPath)
			afterVerb = "entering the repository"
			dirRef = "repository"
		} else {
			step1 = "Clone the repository and thoroughly review the codebase."
			afterVerb = "cloning"
			dirRef = "cloned repository"
		}

		return fmt.Sprintf(
			phase1Template,
			pkg.GitURL,
			pkg.GitBranch,
			commitLine,
			customPrompt,
			contextSection,
			step1,
			afterVerb,
			dirRef,
		)
	}
}

// BuildContinuationPrompt returns a prompt that instructs the security analyst
// to continue a truncated analysis session from where it left off.
//
// It is used by runOpenCodeProcess when an opencode invocation finishes with
// step_finish reason="length", meaning the model's output was cut short by the
// context-window limit before the analysis was complete. The continuation run
// resumes the same opencode session (via --session <sessionID>) so the agent
// can pick up where it stopped.
//
// The prompt assumes the following output files may already be partially
// written by the preceding run and should be updated in place:
//   - output/results.sarif
//   - output/report.md
//   - output/notes.md
func BuildContinuationPrompt() string {
	return `Continue the security analysis from where you left off.

## Instructions

- Do NOT restart the scan or re-clone any repositories.
- Do NOT repeat findings that have already been written to output/results.sarif or output/report.md.
- Focus on the remaining unreviewed files and attack surfaces that were not yet covered.
- Update output/results.sarif and output/report.md IN PLACE, appending only newly discovered findings.
- Update output/notes.md with any new observations.
- If you have already completed all phases of the analysis, write a short completion summary to output/notes.md and stop.

## Reminder

Your previous run was cut short because the output reached the context length limit.
Pick up exactly where you stopped. Do not re-introduce already-reported findings.
Report only newly discovered vulnerabilities and any final completion details.`
}
func BuildMultiPackagePrompt(packages []models.SoftwarePackage, analysisPrompt string, analysisCtx *models.AnalysisContext, preClonedByPackage map[string]string) string {
	var sb strings.Builder
	sb.WriteString("You are a security analyst performing a comprehensive vulnerability assessment.\n\n")
	sb.WriteString("## Target Repositories\n\n")

	for i, pkg := range packages {
		fmt.Fprintf(&sb, "### Package %d: %s\n", i+1, pkg.Name)
		fmt.Fprintf(&sb, "- Repository: %s\n", pkg.GitURL)
		fmt.Fprintf(&sb, "- Branch: %s\n", pkg.GitBranch)
		if pkg.GitCommit != "" {
			fmt.Fprintf(&sb, "- Commit: %s\n", pkg.GitCommit)
		}
		if pkg.AnalysisPrompt != "" {
			fmt.Fprintf(&sb, "- Special instructions: %s\n", pkg.AnalysisPrompt)
		}
		sb.WriteString("\n")
	}

	if ap := strings.TrimSpace(analysisPrompt); ap != "" {
		sb.WriteString("## Additional Instructions\n")
		sb.WriteString(ap)
		sb.WriteString("\n\n")
	}

	// Inject prior context.
	sb.WriteString(formatAnalysisContext(analysisCtx))

	if len(preClonedByPackage) > 0 {
		sb.WriteString("## Pre-cloned Repositories\n")
		sb.WriteString("Some repositories are already cloned locally. Use these paths directly and do NOT clone them again.\n\n")
		for _, pkg := range packages {
			if p := preClonedByPackage[pkg.Name]; p != "" {
				fmt.Fprintf(&sb, "- %s: `%s`\n", pkg.Name, p)
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Your Task\n")
	sb.WriteString(`1. For each package, analyze the corresponding codebase thoroughly. Use pre-cloned local directories when provided; only clone repositories that are not already available locally.
2. Identify security vulnerabilities (see OWASP Top 10, CWE categories, dependency vulnerabilities, secrets, auth issues, crypto weaknesses).
3. For each vulnerability, provide severity, CWE ID, file location, description, and recommended fix.
4. Output findings:
   a. One SARIF file PER PACKAGE at output/<package_name>.sarif (SARIF 2.1.0). Use the package name exactly as listed above (lowercase, no spaces). Each SARIF file should contain ONLY findings from that specific package's repository.
   b. A combined Markdown summary at output/report.md covering all packages
   c. Analyst notes at output/notes.md (key observations, areas needing deeper review, what you focused on vs skipped)

IMPORTANT: Do NOT put all findings in a single results.sarif. Each package MUST have its own separate .sarif file named after the package.

Focus on finding NEW and DIFFERENT issues not already listed in the prior findings above.
Be thorough but precise. Only report genuine vulnerabilities.

## Error Reporting
If you are unable to complete the analysis (e.g. cannot access a repository, missing dependencies,
build failures, or any other blocker), write a concise explanation (under 30 words) to ` + "`output/error.txt`" + `
and stop. Do NOT fabricate findings.`)

	return sb.String()
}
