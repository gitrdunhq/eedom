/**
 * dependencyAdmission — Jenkins Shared Library Step
 *
 * Evaluates dependency changes on pull requests using the Admission Control
 * pipeline (OSV-Scanner, Trivy, Syft, ScanCode, OPA). Fail-open: any tool
 * failure produces a warning, never a build failure.
 *
 * USAGE
 * -----
 * In your Jenkinsfile:
 *
 *   @Library('admission-control') _
 *
 *   pipeline {
 *     agent any
 *     stages {
 *       stage('Dependency Admission') {
 *         steps {
 *           dependencyAdmission(
 *             team:            'platform',
 *             operatingMode:   'advise',       // 'monitor' (default) | 'advise'
 *             enabledScanners: 'syft,osv-scanner,trivy,scancode',
 *             pythonCmd:       'uv run python'
 *           )
 *         }
 *       }
 *     }
 *   }
 *
 * CONFIGURATION OPTIONS
 * ----------------------
 *   team            (required) Team name used for audit trail and PR comments.
 *   operatingMode   'monitor' — log only, no PR comment, no unstable marking.
 *                   'advise'  — post PR comment, mark build UNSTABLE on
 *                               reject/needs_review. Default: 'monitor'.
 *   enabledScanners Comma-separated list of scanners to run.
 *                   Default: 'syft,osv-scanner,trivy,scancode'
 *   pythonCmd       Command used to invoke Python.
 *                   Default: 'uv run python'
 *
 * DEPENDENCY FILES WATCHED
 * -------------------------
 *   requirements*.txt, pyproject.toml, setup.cfg, *.lock, Pipfile, setup.py
 *
 * OPERATING MODES
 * ----------------
 *   monitor  Records decisions to the database and evidence store. Does not
 *            post PR comments and never marks the build unstable. Safe for
 *            initial rollout.
 *   advise   Posts a formatted comment on the PR (or updates an existing one).
 *            Marks the build UNSTABLE (not FAILURE) when the decision is
 *            'reject' or 'needs_review'. The build continues — it is never
 *            failed by this step.
 *
 * INTEGRATION TEST VERIFICATION (manual steps)
 * ----------------------------------------------
 *   1. Open a PR that adds a new entry to requirements.txt.
 *   2. Confirm the stage runs and invokes the CLI (check Console Output).
 *   3. In advise mode: confirm a PR comment appears with the decision badge.
 *   4. Re-run the pipeline: confirm the existing comment is updated, not
 *      duplicated (look for a single comment with the admission-control marker).
 *   5. Introduce a package with a known CVE: confirm build is marked UNSTABLE.
 *   6. Remove the admission control comment manually, re-run: confirm a new
 *      comment is created.
 *   7. In monitor mode: confirm no PR comment is posted and build stays stable
 *      regardless of decision.
 */

// Marker embedded in every PR comment for upsert detection.
private static final String COMMENT_MARKER = '<!-- admission-control-result -->'

// GitHub PR comment character limit with a safety margin.
private static final int MAX_COMMENT_CHARS = 65000

// Dependency file patterns passed to git diff.
private static final List<String> DEP_FILE_PATTERNS = [
    '*.txt', '*.toml', '*.cfg', '*.lock', 'Pipfile', 'setup.py'
]

/**
 * Main entry point called from Jenkinsfiles.
 *
 * @param config  Map of configuration options (see header docs).
 */
def call(Map config = [:]) {
    String team           = config.team           ?: ''
    String operatingMode  = config.operatingMode  ?: 'monitor'
    String enabledScanners = config.enabledScanners ?: 'syft,osv-scanner,trivy,scancode'
    String pythonCmd      = config.pythonCmd      ?: 'uv run python'

    if (!team) {
        echo '[WARN] dependencyAdmission: "team" is required. Skipping admission check.'
        return
    }

    try {
        _runAdmission(team, operatingMode, enabledScanners, pythonCmd)
    } catch (Exception e) {
        // Fail-open: any unexpected exception is downgraded to a warning.
        echo "[WARN] dependencyAdmission: unexpected error — ${e.getMessage()}. Build continues."
    }
}

// ---------------------------------------------------------------------------
// Core pipeline
// ---------------------------------------------------------------------------

private void _runAdmission(
    String team,
    String operatingMode,
    String enabledScanners,
    String pythonCmd
) {
    // 1. Detect whether any dependency files changed.
    String patterns = DEP_FILE_PATTERNS.join(' ')
    String changedFiles = _sh(
        "git diff origin/main...HEAD --name-only -- ${patterns} 2>/dev/null || true"
    ).trim()

    if (!changedFiles) {
        echo '[INFO] dependencyAdmission: No dependency files changed. Skipping.'
        return
    }

    echo "[INFO] dependencyAdmission: Dependency files changed:\n${changedFiles}"

    // 2. Generate the diff and write it to a workspace file (never /tmp).
    String diffFile    = "${env.WORKSPACE}/.admission-diff-${env.BUILD_NUMBER}.patch"
    String decisionFile = "${env.WORKSPACE}/.admission-decision-${env.BUILD_NUMBER}.json"

    _sh(
        "git diff origin/main...HEAD -- ${patterns} > ${diffFile} 2>/dev/null || true"
    )

    // 3. Determine PR URL — available only on multibranch/PR builds.
    String prUrl = env.CHANGE_URL ?: ''

    // 4. Build and run the CLI invocation.
    // User-controlled values (team, operatingMode, prUrl) are passed via withEnv
    // to prevent shell injection via single-quote breakout (F-008). Only pythonCmd
    // (pipeline-author-controlled) and workspace paths are interpolated directly.
    String memoText = ''
    try {
        withEnv([
            "ADMISSION_ENABLED_SCANNERS=${enabledScanners}",
            "AC_TEAM=${team}",
            "AC_MODE=${operatingMode}",
            "AC_PR_URL=${prUrl ?: 'unknown'}",
        ]) {
            String cliCmd = [
                pythonCmd,
                '-m admission_control.cli.main evaluate',
                "--repo-path '${env.WORKSPACE}'",
                "--diff '${diffFile}'",
                '--pr-url "$AC_PR_URL"',
                '--team "$AC_TEAM"',
                '--operating-mode "$AC_MODE"',
                "--output-json '${decisionFile}'",
            ].join(' ')
            memoText = _sh(cliCmd)
        }
        echo "[INFO] dependencyAdmission: CLI completed."
    } catch (Exception e) {
        echo "[WARN] dependencyAdmission: CLI invocation failed — ${e.getMessage()}. Continuing."
    }

    // 6. Read the decision JSON if it was written.
    String decisionVerdict = _readDecisionVerdict(decisionFile)
    echo "[INFO] dependencyAdmission: decision=${decisionVerdict}"

    // 7. In advise mode: post PR comment and optionally mark unstable.
    if (operatingMode == 'advise') {
        if (prUrl) {
            _postPrComment(memoText, decisionVerdict)
        } else {
            echo '[INFO] dependencyAdmission: No CHANGE_URL set — skipping PR comment.'
        }

        if (decisionVerdict in ['reject', 'needs_review']) {
            echo "[WARN] dependencyAdmission: Decision is '${decisionVerdict}' — marking build UNSTABLE."
            currentBuild.result = 'UNSTABLE'
        }
    } else {
        echo '[INFO] dependencyAdmission: monitor mode — skipping PR comment and unstable marking.'
    }

    // 8. Clean up workspace scratch files.
    _cleanupScratch(diffFile, decisionFile)
}

// ---------------------------------------------------------------------------
// Decision JSON reader
// ---------------------------------------------------------------------------

/**
 * Reads the verdict string from the JSON output file.
 * Returns 'unknown' on any failure — never throws.
 */
private String _readDecisionVerdict(String jsonPath) {
    try {
        if (!fileExists(jsonPath)) {
            return 'unknown'
        }
        String raw = readFile(file: jsonPath).trim()
        // Extract "decision": "<value>" without pulling in a JSON library.
        def matcher = raw =~ /"decision"\s*:\s*"([^"]+)"/
        if (matcher.find()) {
            return matcher.group(1)
        }
    } catch (Exception e) {
        echo "[WARN] dependencyAdmission: could not read decision JSON — ${e.getMessage()}"
    }
    return 'unknown'
}

// ---------------------------------------------------------------------------
// PR comment formatting and posting (T-022)
// ---------------------------------------------------------------------------

/**
 * Posts or updates the admission control PR comment.
 * Uses gh CLI for cross-platform compatibility (works with GitHub and GitLab
 * mirrors via the same `gh` wrapper). Falls back gracefully on any error.
 */
private void _postPrComment(String memoText, String decisionVerdict) {
    try {
        String commentBody = formatPrComment(memoText, env.BUILD_URL ?: '')
        String commentFile = "${env.WORKSPACE}/.admission-comment-${env.BUILD_NUMBER}.md"
        writeFile(file: commentFile, text: commentBody)

        // Try to update an existing comment; fall back to creating a new one.
        boolean updated = _updateExistingComment(commentFile)
        if (!updated) {
            _createNewComment(commentFile)
        }

        // Clean up the comment file.
        _sh("rm -f '${commentFile}' 2>/dev/null || true")
    } catch (Exception e) {
        echo "[WARN] dependencyAdmission: PR comment failed — ${e.getMessage()}. Build continues."
    }
}

/**
 * Searches for an existing admission control comment and updates it.
 *
 * @return true if an existing comment was found and updated, false otherwise.
 */
private boolean _updateExistingComment(String commentFile) {
    try {
        String prNumber = env.CHANGE_ID ?: ''
        if (!prNumber) {
            return false
        }

        // List PR comments as JSON and find one containing our marker.
        String listOutput = _sh(
            "gh pr view '${prNumber}' --json comments --jq '.comments[] | select(.body | contains(\"${COMMENT_MARKER}\")) | .databaseId' 2>/dev/null || true"
        ).trim()

        if (!listOutput) {
            return false
        }

        // Take the first match if multiple exist.
        String commentId = listOutput.split('\n')[0].trim()
        if (!commentId || !commentId.isNumber()) {
            return false
        }

        _sh("gh api repos/{owner}/{repo}/issues/comments/${commentId} --method PATCH --field body=@'${commentFile}' 2>/dev/null")
        echo "[INFO] dependencyAdmission: Updated existing PR comment ${commentId}."
        return true
    } catch (Exception e) {
        echo "[WARN] dependencyAdmission: Could not update existing comment — ${e.getMessage()}"
        return false
    }
}

/**
 * Creates a new PR comment.
 */
private void _createNewComment(String commentFile) {
    try {
        String prNumber = env.CHANGE_ID ?: ''
        if (!prNumber) {
            echo '[WARN] dependencyAdmission: CHANGE_ID not set — cannot post PR comment.'
            return
        }
        _sh("gh pr comment '${prNumber}' --body-file '${commentFile}'")
        echo '[INFO] dependencyAdmission: Posted new PR comment.'
    } catch (Exception e) {
        echo "[WARN] dependencyAdmission: Could not create PR comment — ${e.getMessage()}"
    }
}

/**
 * Formats the admission control PR comment body.
 *
 * Includes:
 *   - The COMMENT_MARKER for upsert detection
 *   - A decision badge header
 *   - Full memo wrapped in a collapsible <details> block
 *   - Footer with Jenkins build link and UTC timestamp
 *
 * Kept under MAX_COMMENT_CHARS (65 000) to respect GitHub's limit.
 *
 * @param memo      Markdown memo text produced by the Python CLI.
 * @param buildUrl  Jenkins build URL for the footer link.
 * @return          Formatted comment body string.
 */
String formatPrComment(String memo, String buildUrl) {
    String badge    = _decisionBadge(memo)
    String ts       = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))
    String buildLink = buildUrl ? "[Jenkins build](${buildUrl})" : 'Jenkins build'

    StringBuilder sb = new StringBuilder()
    sb.append(COMMENT_MARKER).append('\n\n')
    sb.append("## ${badge} Dependency Admission Control\n\n")

    // Collapsible full findings block.
    sb.append('<details>\n')
    sb.append('<summary>Full findings (click to expand)</summary>\n\n')
    if (memo?.trim()) {
        sb.append(memo.trim()).append('\n')
    } else {
        sb.append('_No findings reported._\n')
    }
    sb.append('\n</details>\n\n')

    // Footer.
    sb.append("---\n")
    sb.append("_${buildLink} &nbsp;|&nbsp; ${ts}_\n")

    String result = sb.toString()

    // Trim to the GitHub comment character limit.
    if (result.length() > MAX_COMMENT_CHARS) {
        String truncationNotice = '\n\n_[comment truncated — see Jenkins build for full output]_\n'
        result = result.substring(0, MAX_COMMENT_CHARS - truncationNotice.length()) + truncationNotice
    }

    return result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Derives a visual badge from the memo text.
 * Falls back to a neutral badge when the decision cannot be parsed.
 */
private String _decisionBadge(String memo) {
    if (!memo) return '⚪'
    String lower = memo.toLowerCase()
    if (lower.contains('🔴') || lower.contains('rejected'))                  return '🔴'
    if (lower.contains('🟡') || lower.contains('needs review'))              return '🟡'
    if (lower.contains('🟠') || lower.contains('approved with constraints')) return '🟠'
    if (lower.contains('🟢') || lower.contains('approved'))                  return '🟢'
    return '⚪'
}

/**
 * Runs a shell command and returns trimmed stdout.
 * Wraps the Jenkins `sh` step with returnStdout.
 */
private String _sh(String cmd) {
    return sh(script: cmd, returnStdout: true).trim()
}

/**
 * Best-effort cleanup of workspace scratch files.
 */
private void _cleanupScratch(String... paths) {
    try {
        for (String p : paths) {
            _sh("rm -f '${p}' 2>/dev/null || true")
        }
    } catch (Exception ignored) {
        // Cleanup failures are silent — they do not affect pipeline state.
    }
}
