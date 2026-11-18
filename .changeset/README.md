# Changesets

Every pull request that changes the published package adds a changeset:

```bash
npx changeset
```

Pick the bump type (patch / minor / major) and describe the change for users. The release workflow
turns pending changesets into a version bump + CHANGELOG entry and publishes to npm.
