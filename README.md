# Workflows

This folder collects SentinelOne Hyperautomation workflows built for a SOC, automations that detect, enrich, and where appropriate, with analyst approval, respond to security signals across the environment's connected data sources.

Each workflow should generated from live, in-session evidence. More specifically: data source enumeration, field-schema discovery, and taxonomy validation against the actual SentinelOne Data Lake tenant. Every workflow ships with a companion deployment guide covering prerequisites, step-by-step import/configuration, validation, and troubleshooting.

## Claud Cowork

Workflows in this folder are authored with Claude in Cowork mode, using the **sentinelone-hyperautomation** skill, which supplies the Hyperautomation JSON schema, a catalog of reusable building blocks mined from production workflows, and a validation checklist that every generated workflow is checked against before being handed off.

Skill source: [github.com/Sentinel-One/ai-siem — plugins/s1-secops-skills/skills/hyperautomation](https://github.com/Sentinel-One/ai-siem/tree/main/plugins/s1-secops-skills/skills/hyperautomation)

## Example: Netskope Account Takeover

Published here as a worked example:

- [`netskope-ato-hyperautomation-workflow.json`](./netskope/netskope-ato-hyperautomation-workflow.json) is the workflow template. Hunts Netskope-native account-takeover signals like UBA anomaly, compromised credential, login-failed bursts. It thenn enriches the source IP via VirusTotal, and gates an Okta user-suspend behind Slack analyst approval.
- [`netskope-ato-workflow-deployment-guide.md`](./netskope/netskope-ato-workflow-deployment-guide.md) provides the architecture diagram, prerequisites, deployment steps, validation checklist, and troubleshooting for importing and configuring it.
