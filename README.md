# 🛡️ **Spectre IDS Setup & Integration Guide**

This guide explains how to install, configure, and run **Spectre IDS**, as well as how to integrate it with **Wazuh** for centralized alert monitoring.
## Installation

```bash
cd /opt
sudo su
git clone https://github.com/bbbmasterlolz/spectre
cd spectre
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
cp /opt/spectre/spectre_IDS/service/*.service /etc/systemd/system/
```

## Configuration

```bash
nano /opt/spectre/spectre_IDS/config.json
```

## Wazuh Integration

```bash
sudo nano /opt/spectre/spectre_IDS/logs/alerts.json
sudo nano /var/ossec/etc/ossec.conf
```

Add this section inside **ossec.conf**:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/spectre/spectre_IDS/logs/alerts.json</location>
</localfile>
```

Then set file permission:

```bash
sudo chmod 777 /opt/spectre/spectre_IDS/logs/alerts.json
```

Reload systemd:

```bash
sudo systemctl daemon-reload
```

## Auto Start Services

```bash
sudo systemctl enable spectre-web.service
sudo systemctl enable spectre-capture.service
sudo systemctl enable spectre-analyzer.service
```

## Start Services

```bash
sudo systemctl start spectre-web.service
sudo systemctl start spectre-capture.service
sudo systemctl start spectre-analyzer.service
```

## Check Status

```bash
sudo systemctl status spectre-web.service
sudo systemctl status spectre-capture.service
sudo systemctl status spectre-analyzer.service
```
