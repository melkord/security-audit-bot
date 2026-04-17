/**
 * Security Audit & Fix
 *
 * Runs yarn npm audit, updates vulnerable packages, and creates/updates a PR on Bitbucket.
 *
 * Required env vars (set as Secured repository variables in Bitbucket Pipelines):
 *   - AUDIT_BITBUCKET_TOKEN: Bitbucket Repository Access Token
 *     Create at: Repository Settings > Security > Access tokens
 *     Required permissions: Repositories (Write), Pull requests (Write)
 *   - AUDIT_PR_REVIEWERS: comma-separated Bitbucket user UUIDs for PR reviewers (optional)
 *
 * Optional env vars:
 *   - AUDIT_SEVERITY: minimum severity to fix (default: "moderate")
 *   - AUDIT_DRY_RUN: set to "true" to skip push and PR creation
 */
import { execSync } from 'child_process';
import { Bitbucket, Schema, APIClient } from 'bitbucket';

// ─── Config ──────────────────────────────────────────────────────────────────

const CONFIG = {
    workspace: process.env.AUDIT_BITBUCKET_WORKSPACE ?? 'my-workspace',
    repo: process.env.AUDIT_BITBUCKET_REPO ?? 'my-repo',
    baseBranch: process.env.AUDIT_BASE_BRANCH ?? 'develop',
    branchName: process.env.AUDIT_BRANCH_NAME ?? 'fix/security-audit',
    severity: process.env.AUDIT_SEVERITY ?? 'moderate',
    dryRun: process.env.AUDIT_DRY_RUN === 'true',
    date: new Date().toISOString().split('T')[0]!,
    reviewers: process.env.AUDIT_PR_REVIEWERS ? process.env.AUDIT_PR_REVIEWERS.split(',').map(uuid => ({ uuid: uuid.trim() })) : [],
};

const SEVERITY_EMOJI: Record<string, string> = {
    critical: '🔴',
    high: '🟠',
    moderate: '🟡',
    low: '⚪',
};

// ─── Types ───────────────────────────────────────────────────────────────────

interface AuditEntry {
    name: string;
    severity: string;
    vulnerableVersions: string;
    currentVersions: string[];
    workspaces: string[];
}

interface YarnAuditLine {
    value?: string;
    children?: {
        Severity?: string;
        'Vulnerable Versions'?: string;
        'Tree Versions'?: string[];
        Dependents?: string[];
    };
}

// ─── Shell helpers ───────────────────────────────────────────────────────────

function run(cmd: string): string {
    return execSync(cmd, { encoding: 'utf-8' }).trim();
}

function runSafe(cmd: string): string | null {
    try {
        return run(cmd);
    } catch {
        return null;
    }
}

/** Captures stdout even when the command exits with a non-zero code. */
function runCaptureOutput(cmd: string): { stdout: string; exitCode: number } {
    try {
        const stdout = execSync(cmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();

        return { stdout, exitCode: 0 };
    } catch (e) {
        const err = e as { stdout?: string; stderr?: string; status?: number };

        return {
            stdout: (err.stdout || err.stderr || '').trim(),
            exitCode: err.status ?? 1,
        };
    }
}

// ─── Audit parsing ───────────────────────────────────────────────────────────

/**
 * Parses yarn npm audit NDJSON output.
 * Each line: { "value": "pkg-name", "children": { "Severity": "...", ... } }
 */
function parseAuditOutput(raw: string): AuditEntry[] {
    const packages = new Map<string, AuditEntry>();

    for (const line of raw.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        let parsed: YarnAuditLine;

        try {
            parsed = JSON.parse(trimmed);
        } catch {
            continue;
        }

        if (!parsed.value) continue;

        const children = parsed.children ?? {};
        const workspaces = (children.Dependents ?? []).map(d => d.replace(/@workspace:.+$/, ''));
        const existing = packages.get(parsed.value);

        if (existing) {
            for (const ws of workspaces) {
                if (!existing.workspaces.includes(ws)) existing.workspaces.push(ws);
            }
        } else {
            packages.set(parsed.value, {
                name: parsed.value,
                severity: (children.Severity ?? 'unknown').toLowerCase(),
                vulnerableVersions: children['Vulnerable Versions'] ?? 'unknown',
                currentVersions: children['Tree Versions'] ?? [],
                workspaces,
            });
        }
    }

    return [...packages.values()];
}

// ─── Bitbucket API ───────────────────────────────────────────────────────────

function createBitbucketClient(): APIClient {
    const token = process.env.AUDIT_BITBUCKET_TOKEN;
    if (!token) throw new Error('Missing AUDIT_BITBUCKET_TOKEN environment variable');

    return new Bitbucket({ auth: { token } });
}

async function fetchWorkspaceMemberUuids(): Promise<Set<string>> {
    const token = process.env.AUDIT_BITBUCKET_TOKEN;
    if (!token) throw new Error('Missing AUDIT_BITBUCKET_TOKEN');

    const uuids = new Set<string>();
    let url: string | null = `https://api.bitbucket.org/2.0/workspaces/${CONFIG.workspace}/members?pagelen=100`;

    while (url) {
        const res: Response = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });

        if (!res.ok) {
            console.warn(`Failed to fetch workspace members (${res.status}). Skipping reviewer validation.`);

            return new Set();
        }

        const data: { values?: { user?: { uuid?: string } }[]; next?: string } = await res.json();

        for (const member of data.values ?? []) {
            if (member.user?.uuid) uuids.add(member.user.uuid);
        }

        url = data.next ?? null;
    }

    return uuids;
}

async function validateReviewers(): Promise<{ uuid: string }[]> {
    if (CONFIG.reviewers.length === 0) return [];

    console.log(`Validating ${CONFIG.reviewers.length} reviewer UUID(s) against workspace members...`);

    const activeUuids = await fetchWorkspaceMemberUuids();

    // If we couldn't fetch members, pass all reviewers through (let PR creation validate)
    if (activeUuids.size === 0) {
        console.warn('Could not fetch workspace members. Passing all reviewers to PR creation.');

        return CONFIG.reviewers.map(r => ({
            uuid: r.uuid.startsWith('{') ? r.uuid : `{${r.uuid}`,
        }));
    }

    const valid: { uuid: string }[] = [];

    for (const reviewer of CONFIG.reviewers) {
        // Normalize: ensure UUID has curly braces (Bitbucket env vars can strip the opening brace)
        const normalized = reviewer.uuid.startsWith('{') ? reviewer.uuid : `{${reviewer.uuid}`;

        if (activeUuids.has(normalized)) {
            console.log(`  ${normalized} -> OK`);
            valid.push({ uuid: normalized });
        } else {
            console.warn(`  ${normalized} -> not an active workspace member, skipping`);
        }
    }

    if (valid.length === 0) {
        console.warn('No valid reviewers found. PR will be created without reviewers.');
    }

    return valid;
}

async function findExistingPr(bitbucket: APIClient): Promise<number | null> {
    const { data } = await bitbucket.pullrequests.list({
        workspace: CONFIG.workspace,
        repo_slug: CONFIG.repo,
        q: `source.branch.name="${CONFIG.branchName}" AND state="OPEN"`,
    });

    const firstPr = data.values?.[0];

    return firstPr?.id ?? null;
}

async function createOrUpdatePr(bitbucket: APIClient, title: string, description: string, reviewers: { uuid: string }[]): Promise<string> {
    const existingPrId = await findExistingPr(bitbucket);

    const prData: Schema.Pullrequest = {
        type: 'pullrequest',
        title,
        description,
        source: { branch: { name: CONFIG.branchName } },
        destination: { branch: { name: CONFIG.baseBranch } },
        close_source_branch: true,
        ...(reviewers.length > 0 && {
            reviewers: reviewers.map(r => ({ type: 'user', uuid: r.uuid })),
        }),
    };

    let result;

    if (existingPrId) {
        console.log(`Updating existing PR #${existingPrId}...`);
        result = await bitbucket.pullrequests.update({
            workspace: CONFIG.workspace,
            repo_slug: CONFIG.repo,
            pull_request_id: existingPrId,
            _body: prData,
        });
    } else {
        console.log('Creating new PR...');
        result = await bitbucket.pullrequests.create({
            workspace: CONFIG.workspace,
            repo_slug: CONFIG.repo,
            _body: prData,
        });
    }

    const url = result.data.links?.html?.href;

    if (!url) {
        console.error('PR response:', JSON.stringify(result.data, null, 2));
        throw new Error('Bitbucket API did not return a PR URL');
    }

    return url;
}

async function commentOnStalePr(): Promise<void> {
    const bitbucket = createBitbucketClient();
    const prId = await findExistingPr(bitbucket);

    if (!prId) return;

    console.log(`Found open PR #${prId} but no vulnerabilities remain. Adding comment...`);

    const comment: Schema.PullrequestComment = {
        type: 'pullrequest_comment',
        content: {
            raw: `⚠️ **Audit run ${CONFIG.date}**: no vulnerabilities found on \`${CONFIG.baseBranch}\`. This PR may no longer be needed.`,
        },
    };

    await bitbucket.pullrequests.createComment({
        workspace: CONFIG.workspace,
        repo_slug: CONFIG.repo,
        pull_request_id: prId,
        _body: comment,
    });

    console.log('Comment added.');
}

// ─── PR description ──────────────────────────────────────────────────────────

function buildAuditTable(entries: AuditEntry[]): string {
    const header = '| Package | Severity | Vulnerable | Installed | Workspace |';
    const divider = '|---------|----------|-----------|-----------|-----------|';
    const rows = entries.map(e => {
        const emoji = SEVERITY_EMOJI[e.severity] ?? '⚪';
        const versions = e.currentVersions.join(', ') || '?';
        const workspaces = e.workspaces.map(w => `\`${w}\``).join(', ') || '?';

        return `| ${e.name} | ${emoji} ${e.severity} | ${e.vulnerableVersions} | ${versions} | ${workspaces} |`;
    });

    return [header, divider, ...rows].join('\n');
}

function buildPrDescription(updatedEntries: AuditEntry[], failedEntries: AuditEntry[]): string {
    const sections: string[] = [
        '## 🔒 Security Audit Fix',
        '',
        'Automated PR created by the scheduled security audit pipeline.',
        '',
        `**Severity threshold**: \`${CONFIG.severity}\` | **Date**: ${CONFIG.date}`,
    ];

    if (updatedEntries.length > 0) {
        sections.push('', '### 📦 Updated packages', '', buildAuditTable(updatedEntries));
    }

    if (failedEntries.length > 0) {
        sections.push(
            '',
            '### ⚠️ Failed to update',
            '',
            'These packages are transitive dependencies (dependencies of your dependencies).',
            'They can only be fixed when the parent package releases a version with the updated dependency.',
            '',
            buildAuditTable(failedEntries)
        );
    }

    sections.push('', '### ✅ Next steps', '- Review the package updates', '- Verify CI passes', '- Merge if all checks are green');

    return sections.join('\n');
}

// ─── Git helpers ─────────────────────────────────────────────────────────────

function checkoutDevelop(): void {
    // -B creates or resets the branch (works even if we're already on develop)
    run(`git checkout -B ${CONFIG.baseBranch} FETCH_HEAD`);
    console.log('Installing dependencies on develop...');
    run('yarn install');
}

function createBranchFromBase(): void {
    if (runSafe(`git rev-parse --verify ${CONFIG.branchName}`) !== null) {
        run(`git branch -D ${CONFIG.branchName}`);
    }

    run(`git checkout -b ${CONFIG.branchName}`);
}

function cleanupBranch(): void {
    run(`git checkout ${CONFIG.baseBranch}`);
    runSafe(`git branch -D ${CONFIG.branchName}`);
}

function hasChanges(): boolean {
    return runSafe('git diff --quiet') === null || runSafe('git diff --cached --quiet') === null;
}

function commitAndPush(message: string): void {
    run('git add -A');
    run(`git commit -m ${JSON.stringify(message)}`);
    run(`git push --force origin ${CONFIG.branchName}`);
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
    console.log(`=== Security Audit (severity >= ${CONFIG.severity}) ===`);

    // 1. Switch to develop and run audit
    checkoutDevelop();

    const audit = runCaptureOutput(`yarn npm audit --all --severity ${CONFIG.severity} --environment production --json`);

    if (audit.exitCode === 0) {
        console.log('No vulnerabilities found.');

        try {
            await commentOnStalePr();
        } catch (e) {
            console.warn('Failed to comment on stale PR (non-blocking):', (e as Error).message);
        }

        process.exit(0);
    }

    if (!audit.stdout) {
        console.error(`yarn npm audit exited with code ${audit.exitCode} but produced no output.`);
        console.error('This usually means a network or authentication error, not a vulnerability report.');
        process.exit(1);
    }

    // Detect non-JSON output (e.g. error messages from yarn itself)
    const firstLine = audit.stdout.split('\n')[0]?.trim() ?? '';
    if (firstLine && !firstLine.startsWith('{')) {
        console.error('yarn npm audit returned unexpected output (expected NDJSON):');
        console.error(audit.stdout.slice(0, 500));
        process.exit(1);
    }

    console.log('Raw audit output:');
    console.log(audit.stdout);
    console.log('');

    // 2. Parse results
    const auditEntries = parseAuditOutput(audit.stdout);

    if (auditEntries.length === 0) {
        console.error('Audit output was valid JSON but contained no vulnerability entries.');
        console.error('The yarn audit output format may have changed.');
        process.exit(1);
    }

    console.log(`Found ${auditEntries.length} vulnerable package(s):`);
    auditEntries.forEach(e => console.log(`  - ${e.name} (${e.severity})`));
    console.log('');

    // 3. Create branch from develop and update packages
    createBranchFromBase();

    console.log('=== Updating packages ===');
    const updated: string[] = [];
    const failed: string[] = [];

    for (const { name } of auditEntries) {
        console.log(`Updating ${name}...`);

        if (runSafe(`yarn up ${name}`) !== null) {
            updated.push(name);
            console.log('  OK');
        } else {
            failed.push(name);
            console.log('  FAILED (may be a transitive dependency)');
        }
    }

    // Reinstall to ensure lockfile and node_modules are consistent after updates
    if (updated.length > 0) {
        console.log('\nRunning yarn install to consolidate changes...');
        run('yarn install');
    }

    // 4. Check for actual file changes
    if (!hasChanges()) {
        console.error('No file changes after updating. All vulnerable packages may be transitive dependencies that cannot be directly updated.');
        console.error('Failed packages:', failed.length > 0 ? failed.join(', ') : 'none');
        console.error('Updated packages:', updated.length > 0 ? updated.join(', ') : 'none');
        cleanupBranch();
        process.exit(1);
    }

    // 5. Commit
    const commitMsg = [
        `fix: update packages with known vulnerabilities (${CONFIG.date})`,
        '',
        'Automated security audit fix.',
        `Severity threshold: ${CONFIG.severity}`,
        updated.length > 0 ? `\nUpdated:\n${updated.map(p => `- ${p}`).join('\n')}` : '',
        failed.length > 0 ? `\nFailed to update (transitive):\n${failed.map(p => `- ${p}`).join('\n')}` : '',
    ]
        .filter(Boolean)
        .join('\n');

    if (CONFIG.dryRun) {
        console.log('\n=== DRY RUN - Skipping push and PR creation ===');
        cleanupBranch();
        process.exit(0);
    }

    // 6. Push and create PR
    commitAndPush(commitMsg);

    console.log('\n=== Creating Pull Request ===');

    const bitbucket = createBitbucketClient();
    const validReviewers = await validateReviewers();
    const updatedEntries = auditEntries.filter(e => updated.includes(e.name));
    const failedEntries = auditEntries.filter(e => failed.includes(e.name));
    const prDescription = buildPrDescription(updatedEntries, failedEntries);

    const prUrl = await createOrUpdatePr(bitbucket, `🔒 security audit - update vulnerable packages (${CONFIG.date})`, prDescription, validReviewers);

    console.log(`PR created: ${prUrl}`);
}

main().catch(e => {
    console.error(e);
    process.exit(1);
});
