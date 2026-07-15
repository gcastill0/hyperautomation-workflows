# Workflows

This folder collects SentinelOne Hyperautomation workflows built for this SOC — automations that detect, enrich, and (where appropriate, with analyst approval) respond to security signals across the environment's connected data sources, rather than leaving that correlation work to manual triage.

Each workflow here is generated from live, in-session evidence — data source enumeration, field-schema discovery, and taxonomy validation against the actual SentinelOne Data Lake tenant — not from assumed or templated field names. Every workflow ships with a companion deployment guide covering prerequisites, step-by-step import/configuration, validation, and troubleshooting.

## How these are built

Workflows in this folder are authored with Claude (in Cowork mode) using the **sentinelone-hyperautomation** skill, which supplies the Hyperautomation JSON schema, a catalog of reusable building blocks mined from production workflows, and a validation checklist that every generated workflow is checked against before being handed off.

Skill source: [github.com/Sentinel-One/ai-siem — plugins/s1-secops-skills/skills/hyperautomation](https://github.com/Sentinel-One/ai-siem/tree/main/plugins/s1-secops-skills/skills/hyperautomation)

## Example: Netskope Account Takeover

Published here as a worked example:

- [`netskope-ato-hyperautomation-workflow.json`](./netskope/netskope-ato-hyperautomation-workflow.json) — the workflow itself. Hunts Netskope-native account-takeover signals (UBA anomaly, compromised credential, login-failed bursts), enriches the source IP via VirusTotal, and gates an Okta user-suspend behind Slack analyst approval.
- [`netskope-ato-workflow-deployment-guide.md`](./netskope/netskope-ato-workflow-deployment-guide.md) — architecture diagram, prerequisites, deployment steps, validation checklist, and troubleshooting for importing and configuring it.

## Adding a new workflow

1. Enumerate data sources and confirm field schema live against the target tenant — never reuse a schema from a prior session or another tenant.
2. Use the sentinelone-hyperautomation skill to generate and validate the workflow JSON.
3. Write a companion deployment guide alongside it, following the pattern set by the Netskope example.
