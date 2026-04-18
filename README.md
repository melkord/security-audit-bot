# Security Audit Automation

Automated dependency audit for Yarn v2+ projects on Bitbucket. Runs `yarn npm audit`, updates vulnerable packages, and creates or updates a Pull Request.

> Companion code for [Dependabot for Bitbucket: building a security audit pipeline](https://melkord.github.io/dependabot-bitbucket-security-audit/).

---

## Architecture

The entire script lives in a single `index.ts` file. This is intentional: the script is meant to run inside a CI pipeline step, where you want the smallest possible footprint. No build step, no bundling, no compiled output to manage. The pipeline installs dependencies, runs the script with `ts-node`, and that's it. Keeping everything in one file also makes it straightforward to copy and adapt to your own project without importing a library or wiring up a plugin system.

---

## Requirements

The **target project** (the one being audited) must use Yarn Berry (v2+), since the script runs `yarn npm audit` and `yarn up` internally.

The script itself requires:
* Node.js >= 18
* A Bitbucket access token with **Repositories: Write** and **Pull requests: Write** permissions

---

## Environment Variables

### Required

| Variable                    | Description                               |
| --------------------------- | ----------------------------------------- |
| `AUDIT_BITBUCKET_TOKEN`     | Bitbucket token used to create/update PRs |
| `AUDIT_BITBUCKET_WORKSPACE` | Bitbucket workspace slug                  |
| `AUDIT_BITBUCKET_REPO`      | Bitbucket repository slug                 |

### Optional

| Variable             | Default              | Description                                              |
| -------------------- | -------------------- | -------------------------------------------------------- |
| `AUDIT_SEVERITY`     | `moderate`           | Minimum severity (`low`, `moderate`, `high`, `critical`) |
| `AUDIT_DRY_RUN`      | `false`              | If `true`, skips branch push and PR creation             |
| `AUDIT_PR_REVIEWERS` | -                    | Comma-separated reviewer UUIDs                           |
| `AUDIT_BASE_BRANCH`  | `develop`            | Target branch for the PR                                 |
| `AUDIT_BRANCH_NAME`  | `fix/security-audit` | Working branch created by the script                     |

---

## Usage

### Bitbucket Pipelines

```yaml
pipelines:
  custom:
    security-audit:
      - step:
          name: Security Audit
          script:
            - npm install --prefix /path/to/security-audit-bot
            - npx --prefix /path/to/security-audit-bot ts-node index.ts
```

> The env vars above (`AUDIT_BITBUCKET_TOKEN`, `AUDIT_BITBUCKET_WORKSPACE`, `AUDIT_BITBUCKET_REPO`) must be set as [repository variables](https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/) in Bitbucket.

### Locally

```bash
npm install
AUDIT_BITBUCKET_TOKEN=xxx AUDIT_BITBUCKET_WORKSPACE=my-ws AUDIT_BITBUCKET_REPO=my-repo npm start
```

### Dry run

Test without pushing or creating a PR:

```bash
AUDIT_DRY_RUN=true npm start
```

---

## Workflow

1. Checkout base branch (default: `develop`)
2. Run `yarn npm audit --all --severity <level> --json`
3. Parse audit results (NDJSON)
4. Create working branch (default: `fix/security-audit`)
5. Run `yarn up <package>` for each vulnerable package
6. Reinstall dependencies to sync the lockfile
7. Commit, push, and create/update the Pull Request

---

## Notes

* Some vulnerabilities come from **transitive dependencies** and cannot be fixed directly. The script reports these separately in the PR.
* The script uses `yarn up`, which updates to the latest version within the semver range. This may introduce breaking changes.

---

## Limitations

* Bitbucket only (no GitHub/GitLab support)
* Relies on Yarn v2+ audit output format

---

## License

MIT
