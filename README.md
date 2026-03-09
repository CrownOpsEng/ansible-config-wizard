# Ansible Config Wizard

Reusable local configuration wizard for Ansible deployment repositories.

## Design

This package owns the generic workflow:

- schema-driven sections and fields
- branching prompt flow
- local secret generation
- file rendering and atomic writes
- optional audit logging
- optional `ansible-vault` encryption
- optional post-write preflight execution

Consumer repositories own their deployment-specific pieces:

- wizard profile YAML
- Jinja output templates
- optional builder hooks for repo-specific derived values

## Local development

```bash
uv venv
uv sync
uv run pytest
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
