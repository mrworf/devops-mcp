# Branch Protection

The `quality-gates` GitHub Actions job runs `npm ci`, `npm run build`, and `npm test` on pull requests and pushes.

To make failed checks block merges into `main`, configure a GitHub branch protection rule or ruleset for `main` that requires the `quality-gates` status check before merging. Workflow YAML reports the check result; GitHub repository settings enforce the merge block.
