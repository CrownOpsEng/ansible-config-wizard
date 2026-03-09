# Ansible Config Wizard

Reusable local configuration wizard for Ansible deployment repositories.

This repository is intended to be public on GitHub as a shared tooling repository.
The package is not intended for PyPI publication yet, so the project metadata includes
the `Private :: Do Not Upload` classifier to block accidental uploads while the API and
release process are still being stabilized.

License: MIT. See [LICENSE](LICENSE).

## Design

This package owns the generic workflow:

- schema-driven sections and fields
- branching prompt flow
- local secret generation
- generated SSH keypair materialization for first-run bootstrap flows
- optional pause and resume checkpoints with saved state
- file rendering and atomic writes
- optional audit logging
- optional `ansible-vault` encryption
- optional post-write preflight execution

Secret-bearing runtime artifacts such as generated bootstrap SSH keys, resume-state files, and audit logs default to the local state directory, not the repo checkout:

- `$ANSIBLE_CONFIG_WIZARD_STATE_HOME` when set
- otherwise `$XDG_STATE_HOME/ansible-config-wizard`
- otherwise `~/.local/state/ansible-config-wizard`

Consumer repositories own their deployment-specific pieces:

- wizard profile YAML
- Jinja output templates
- optional builder hooks for repo-specific derived values

## Local development

```bash
uv venv
uv sync --group dev
uv run pytest
uv run python -m build
```

## Consumer repo pattern

Typical consumer layout:

```text
repo/
  wizard_profiles/
    site.yml
  wizard_templates/
    site/
      all.yml.j2
      vault.yml.j2
  wizard_support/
    builders.py
```

Then run:

```bash
uv run --project ../ansible-config-wizard ansible-config-wizard \
  --profile ./wizard_profiles/site.yml \
  --repo-root .
```

The `builder` field in the profile should reference a callable using `module:callable` syntax, for example:

```yaml
builder: wizard_support.builders:build_site_context
```

## Release notes

- Remove the `Private :: Do Not Upload` classifier only when you are ready to publish distribution artifacts to an index such as PyPI.
