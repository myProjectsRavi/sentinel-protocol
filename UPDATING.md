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

For release publication, Sentinel's GitHub workflow validates the tag/package version identity, tests the packed npm artifact through both fresh and repeat bootstrap paths, publishes the immutable npm version, and verifies that npm's `latest` dist-tag resolves to the newly published version.
