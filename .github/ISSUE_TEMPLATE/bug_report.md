---
name: Bug report
about: Something does not work as documented
title: ""
labels: bug
assignees: ""
---

<!-- Security problem? Do NOT open a public issue. Use the private advisory form: see SECURITY.md. -->
<!-- A wrong verdict from a rule delivered by the rules feed (a feed #<seq> rule)? Open the issue in https://github.com/DonSosiska/panoptes-rules instead. -->
<!-- Remove tokens, keys, passwords and private hostnames from everything you paste. -->

**What happened**

**What you expected**

**Steps to reproduce**

1.
2.

**Environment**

- Panoptes version (`panoptes-server -version`, `panoptes-agent -version`):
- Server installed as (Docker Compose / .deb / .rpm / binary):
- Affected host distribution and version (`/etc/os-release`):
- Agent mode (systemd split services / `-mode all` / agentless local agent):
- Rules feed enabled (yes / no), and the rule layer in question (built-in / feed #<seq> / local):

**Logs**

<!-- journalctl -u panoptes-server / panoptes-agent / panoptes-collector, or docker compose logs -->

```
```

**Additional context**

<!-- For a wrong verdict: the rule ID, the verdict reason shown on the finding, and the relevant facts from
`panoptes-agent -print-facts` (remove anything private). Also the finding URL, anything else. -->
