# Quick start

A 15-minute path: one server that monitors its own host (agentless mode), your first findings in the
web UI, a Matrix alert, and then a first remote agent. For a production rollout read
[installation.md](installation.md) and the
[hardening checklist](security-model.md#operator-hardening-checklist) afterwards.

You need a Linux host with systemd (the one to monitor), root access, and outbound HTTPS. A Matrix
bot is optional until step 5.

Contents: [1 Install the server](#1-install-the-server) - [2 Configure and start](#2-configure-and-start) -
[3 First findings](#3-see-the-first-findings) - [4 Read a finding](#4-read-a-finding) -
[5 Matrix alert](#5-get-a-matrix-alert) - [6 First remote agent](#6-add-a-remote-agent) -
[Next](#where-next)

## 1. Install the server

Download the `.deb` or `.rpm` of a release from the
[releases page](https://github.com/DonSosiska/holealign/releases), verify it
([installation.md](installation.md#verifying-releases)) and install it:

```sh
sudo apt install ./holealign-server_X.Y.Z_amd64.deb      # Debian, Ubuntu
# sudo dnf install ./holealign-server_X.Y.Z_<arch>.rpm   # RHEL family
```

No release yet, or you prefer containers? The Compose path in
[installation.md](installation.md#docker-compose) runs the same server, but agentless mode inside a
container scans the container, not the host. For this quick start use the package.

## 2. Configure and start

Create the secrets file, then switch on agentless mode:

```sh
sudo install -m 0600 /dev/null /etc/holealign/server.env
echo "HOLEALIGN_ADMIN_PASSWORD=$(openssl rand -base64 18)" | sudo tee -a /etc/holealign/server.env >/dev/null
sudo grep HOLEALIGN_ADMIN_PASSWORD /etc/holealign/server.env      # note it: you log in as "admin"
```

Edit `/etc/holealign/server.yaml` (the package installs a copy of the annotated example) and set:

```yaml
local_agent:
  enabled: true
  source: inprocess      # simplest: the server collects its own host
  labels: [server]
```

`inprocess` runs the collectors with the server's own, unprivileged rights, so some facts that need
root (`sshd -T`, `nginx -T`, Docker) are missing and the matching rules answer `conditions_unknown`.
It is fine to learn the product. For real use switch to `source: collector` with the root collector,
see [installation.md](installation.md#agentless-mode).

Start it and watch the log:

```sh
sudo systemctl enable --now holealign-server
journalctl -u holealign-server -f
```

Look for these lines, in about this order: `holealign-server listening` (twice, agent API and admin
UI), `local agent source: inprocess`, `local host provisioned`, `waiting for the vulnerability DB before
the first inventory upload`, and `grype db loaded`. The first start downloads the Grype database
(about 100 MB), so allow a few minutes. Problems: [troubleshooting.md](troubleshooting.md).

## 3. See the first findings

The admin UI listens on loopback only. From your workstation:

```sh
ssh -L 8081:127.0.0.1:8081 you@your-server
```

Open <http://127.0.0.1:8081> and log in as `admin` with the password from step 2. Then:

1. **Hosts** shows your server with a "local (built-in)" badge, after its first check-in.
2. When the first inventory has been scanned and matched (minutes, longer on a big system), **Dashboard**
   fills: the cards count *Exploitable*, *Needs attention*, *Background*, *Not exploitable*.
3. Most findings are `conditions_unknown`: no rule covers that CVE yet. That is normal, and it means
   "cannot tell", not "safe". Open **Findings**: it shows the *needs attention* tier by default
   (KEV, high EPSS, or Critical/High with a fix available).

Nothing appearing after ten minutes: [troubleshooting.md](troubleshooting.md#no-findings-or-wrong-verdicts).

## 4. Read a finding

Click a CVE, then one package. The **Verdict** box gives the verdict and the reason; **Package** shows the
version and the fixed version; **Fix command** gives a package-manager command to upgrade. What each
verdict means and what to do: [user-guide.md](user-guide.md#verdicts-and-what-to-do). The eight
shipped rules decide, for example, regreSSHion (CVE-2024-6387), Terrapin and HTTP/2 Rapid Reset
([rules.md](rules.md#shipped-rules)). To get more rules without writing them, enable the signed
public feed:

```yaml
# /etc/holealign/server.yaml
rules:
  feed:
    enabled: true
    url: https://donsosiska.github.io/holealign-rules/latest.json
    trusted_keys: ["UuFW4nYSCwI3xfHhwapVhYrjYhVO6i7yaxOTv9KFCuM="]
```

Check the key against
<https://github.com/DonSosiska/holealign-rules/blob/main/keys/rules-public.key> first, then
`sudo systemctl restart holealign-server`. The Dashboard then shows a *Rules feed* box
([rules-feed.md](rules-feed.md)).

## 5. Get a Matrix alert

You need a bot account, its access token, and a room the bot has joined; the steps are in
[notifications.md](notifications.md#matrix) (Slack and Telegram work the same way, see
[Slack](notifications.md#slack) and [Telegram](notifications.md#telegram)). Then:

```sh
echo 'HOLEALIGN_MATRIX_TOKEN=syt_...' | sudo tee -a /etc/holealign/server.env >/dev/null
```

```yaml
# /etc/holealign/server.yaml
matrix:
  homeserver: https://matrix.example.com
notify:
  default: ["!yourroom:matrix.example.com"]   # internal room ID, not an alias
```

```sh
sudo systemctl restart holealign-server
journalctl -u holealign-server | grep 'matrix channel'    # "matrix channel enabled"
```

Alerts are sent for `exploitable` findings and for unknown findings that are in KEV or Critical. A
healthy host may have none, so you may wait for the first real alert. If a delivery fails, the dashboard
shows an *Alert delivery problems* banner with the HTTP status. The routes by label (`prod`, `web`, ...)
can be edited under Settings.

## 6. Add a remote agent

On the server, create an enrollment token for the host, with labels that pick the Matrix rooms:

```sh
sudo holealign-server token create web-01 -labels prod,web -max-hosts 1 -expires 24h
```

Agents require `https://`, so the agent port (8080) needs TLS first: native `tls_cert` and `tls_key`, or
a reverse proxy ([installation.md](installation.md#tls)). With a private CA give agents `--ca-file`.

On the monitored host, as root: save the token to a file, fetch `install.sh` from the release tag, read
it, run it:

```sh
V=X.Y.Z
install -m 0600 /dev/null /root/holealign.token && vi /root/holealign.token   # paste the pt_... token
curl --proto '=https' --tlsv1.2 -fsSLO https://raw.githubusercontent.com/DonSosiska/holealign/v$V/deploy/install.sh
less install.sh
sudo sh install.sh --version $V --server https://holealign.example.com --token-file /root/holealign.token
journalctl -u holealign-agent -f
```

`install.sh` needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) to verify the
release. The host appears on the **Hosts** page after its first check-in and gets findings after the
first inventory. For a private CA, pinning, air-gapped hosts and every flag:
[installation.md](installation.md#agents).

## Where next

- Learn the UI: [user-guide.md](user-guide.md).
- Run it for real: [operations.md](operations.md), [configuration.md](configuration.md),
  [security-model.md](security-model.md).
- Write or review rules: [rules.md](rules.md); LLM drafts: [llm.md](llm.md).
- Something broke: [troubleshooting.md](troubleshooting.md).
