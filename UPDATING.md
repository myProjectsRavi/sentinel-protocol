# Updating Sentinel Protocol

Sentinel's canonical npm command is intentionally the same for a first install and for moving an existing local setup to the newest published release:

```bash
npx --yes --package sentinel-protocol@latest sentinel bootstrap --profile minimal --dashboard
```

## New users

On the first bootstrap, Sentinel creates the local configuration (by default under Sentinel's local home), applies the requested initialization profile, runs doctor checks, and starts the local service/dashboard.

Use a different initialization profile if desired:

```bash
npx --yes --package sentinel-protocol@latest sentinel bootstrap --profile standard --dashboard
npx --yes --package sentinel-protocol@latest sentinel bootstrap --profile paranoid --mode enforce --dashboard
```

## Existing users

Run the same canonical command again:

```bash
npx --yes --package sentinel-protocol@latest sentinel bootstrap --profile minimal --dashboard
```

`@latest` asks npm for the current release. When Sentinel finds an existing configuration, bootstrap validates it and applies only explicit versioned migrations when required. A migration is backed up by Sentinel's config migration path. A current-version configuration is preserved rather than being replaced by the `minimal` initialization profile carried in the command.

This means an existing user's persisted mode, engine choices, provider settings, budgets, and other local configuration remain authoritative after updating.

### Intentional reset

Use `--force` only when you intentionally want bootstrap to overwrite the existing configuration and persist the requested initialization profile:

```bash
npx --yes --package sentinel-protocol@latest sentinel bootstrap --force --profile minimal --dashboard
```

### Temporary profile override

If you want to keep the persisted configuration but run a different profile for one invocation, use the normal start command instead of forcing bootstrap:

```bash
npx --yes --package sentinel-protocol@latest sentinel start --profile standard --dashboard
```

## Verify the installed release

```bash
npx --yes --package sentinel-protocol@latest sentinel --version
```

## Automatic GitHub/npm release synchronization

A stable version bump in `package.json` is Sentinel's release intent. After that version reaches `main`, the `release-sync` workflow waits for both CI and the adversarial security scan to succeed on the exact same `main` commit. It then reruns release-specific package and performance validation, publishes the npm package through npm Trusted Publishing/OIDC, creates or verifies the matching `v<version>` Git tag and GitHub Release without moving an existing tag, and verifies that npm's `latest` dist-tag resolves to the same version.

The publish step intentionally happens before creating a missing GitHub tag. If npm rejects authentication or publication, Sentinel therefore does not create a new release tag and cannot leave GitHub ahead of npm. The workflow is idempotent: if npm publication succeeded but GitHub release creation was interrupted, a rerun recognizes the already-published version and completes the GitHub side after revalidating the exact current `main` commit.

Normal `main` commits that do not change the package version are a fast no-op, so Sentinel does not publish a new npm artifact for every commit. If an automatic run ever needs to be recovered, the same workflow can be started manually with `workflow_dispatch`; it still requires the current `main` SHA to have green CI and security-scan evidence before it can release.

### npm Trusted Publisher configuration

The `sentinel-protocol` package must authorize the exact GitHub Actions publisher below in npm package settings:

- Publisher: GitHub Actions
- Organization or user: `myProjectsRavi`
- Repository: `sentinel-protocol`
- Workflow filename: `release.yml`
- Environment: leave unset unless the workflow is later moved behind a GitHub Environment
- Allowed action: `npm publish`

The repository workflow grants `id-token: write` and uses a GitHub-hosted runner. The publish step uses npm CLI 11.5.1, meeting npm's Trusted Publishing client requirement without storing a long-lived npm write token in GitHub Secrets.

The canonical install/update command therefore stays stable while GitHub Release, the npm package version, and npm `latest` are kept synchronized automatically for every intentional version bump.
