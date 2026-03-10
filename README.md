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

When a consumer profile wants the wizard to manage the long-term Ansible SSH identity, it should point the key path at `{{ wizard_ssh_dir }}`, which defaults to:

- `$ANSIBLE_CONFIG_WIZARD_SSH_HOME/<repo>` when `ANSIBLE_CONFIG_WIZARD_SSH_HOME` is set
- otherwise `~/.ssh/ansible-config-wizard/<repo>`

The shared action layer also supports an `ssh_setup` action for first-run host access:

- prints copy-friendly `ssh-copy-id`, `ssh`, and resume commands
- writes those commands to an executable script in the wizard run directory
- can install the managed public key immediately with a one-shot password prompt
- disables agent-based key offers during that install step to avoid `Too many authentication failures`

Wizard-generated resume-state files are best-effort securely deleted after a successful resumed run:

- `shred --remove --zero` when `shred` is available
- otherwise an overwrite-and-unlink fallback

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

When `inventories/prod/group_vars/vault.yml` is already encrypted, the wizard will either use `--vault-password-file`, an `ANSIBLE_VAULT_PASSWORD_FILE` / `ansible.cfg` default, or fall back to Ansible's interactive vault password prompt during preflight.

The `builder` field in the profile should reference a callable using `module:callable` syntax, for example:

```yaml
builder: wizard_support.builders:build_site_context
```

## Release notes

- Remove the `Private :: Do Not Upload` classifier only when you are ready to publish distribution artifacts to an index such as PyPI.
