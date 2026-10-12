# GitHub repository settings

Settings live on GitHub, not in the repository, so they are recorded here to be repeatable. Apply with the `gh` CLI (needs admin rights).

## Security features
```bash
gh api -X PUT repos/gasthecreator/tierfs/vulnerability-alerts                      # Dependabot alerts
gh api -X PUT repos/gasthecreator/tierfs/automated-security-fixes                  # Dependabot security updates
gh api -X PUT repos/gasthecreator/tierfs/private-vulnerability-reporting           # "Report a vulnerability" (SECURITY.md relies on it)
gh api -X PATCH repos/gasthecreator/tierfs -f 'security_and_analysis[secret_scanning][status]=enabled' \
                                           -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
gh api -X PUT repos/gasthecreator/tierfs/actions/permissions/workflow -f default_workflow_permissions=read
```

## Branch ruleset for `main`
Pull request required; the `tests (no mounts)` check required and branch up to date; no force pushes; no deletions; linear history; conversations
resolved. A one-person repository cannot require a second reviewer, so approvals are left at 0 until there is a second maintainer (then require
1 approval and code-owner review, which activates `.github/CODEOWNERS`).
```bash
gh api -X POST repos/gasthecreator/tierfs/rulesets --input - <<'JSON'
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    { "type": "pull_request", "parameters": { "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false, "require_last_push_approval": false, "required_review_thread_resolution": true } },
    { "type": "required_status_checks", "parameters": { "strict_required_status_checks_policy": true,
        "required_status_checks": [ { "context": "tests (no mounts)" } ] } }
  ]
}
JSON
```

## Repository metadata
Description, topics (`filesystem`, `macos`, `fuse`, `cpp`, `storage`, `encryption`), and a link to `docs/README.md`.
