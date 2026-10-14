#!/bin/sh
# Signalling host (Rocky Linux / RHEL family), as root. See README.md, "Deployment".
# Re-running is safe. The service starts only once the TLS certificate is installed (§4).
#
#   scp deploy/signal-host.sh deploy/xfs-signalling.service deploy/90-xfs.conf bin/linux/xfs-signalling <host>:xfs-deploy/
#   scp <secret file> <host>:xfs-deploy/turn-secret        # same file as the TURN host's
#   ssh root@<host> 'sh xfs-deploy/signal-host.sh'
set -eu
here=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

echo "== 1. remove what this host does not need (web server, Cockpit on 9090)"
systemctl disable --now nginx cockpit.socket 2>/dev/null || true
dnf remove -y -q nginx nginx-core 'cockpit*' 2>/dev/null || true

echo "== 2. system update, swap (1 GB RAM), kernel parameters"
dnf -y -q upgrade
if ! swapon --show | grep -q /swapfile; then
	[ -f /swapfile ] || { dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none; chmod 600 /swapfile; mkswap /swapfile >/dev/null; }
	swapon /swapfile
	grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap defaults 0 0' >> /etc/fstab
fi
install -m 644 "$here/90-xfs.conf" /etc/sysctl.d/90-xfs.conf
sysctl --system >/dev/null

echo "== 3. service user, files"
id xfs-signal >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin xfs-signal
install -d -m 750 -g xfs-signal /etc/xfs /etc/xfs/tls
if [ -f "$here/turn-secret" ]; then
	install -m 640 -g xfs-signal "$here/turn-secret" /etc/xfs/turn-secret
	rm -f "$here/turn-secret"
fi
[ -s /etc/xfs/turn-secret ] || { echo "missing /etc/xfs/turn-secret"; exit 1; }
# Certificate uploaded as tls-fullchain.pem / tls-privkey.pem (deploy.ps1). Replacing the
# files is enough on renewal: the service reloads them within a minute, no restart.
if [ -f "$here/tls-fullchain.pem" ] && [ -f "$here/tls-privkey.pem" ]; then
	install -m 640 -g xfs-signal "$here/tls-fullchain.pem" /etc/xfs/tls/fullchain.pem
	install -m 640 -g xfs-signal "$here/tls-privkey.pem" /etc/xfs/tls/privkey.pem
	rm -f "$here/tls-fullchain.pem" "$here/tls-privkey.pem"
fi
# Per-region ICE lists and the offline country database (DB-IP Lite, CC BY 4.0; deploy.ps1
# downloads the current month). Only country codes are looked up; no address is kept for it.
install -m 640 -g xfs-signal "$here/regions.json" /etc/xfs/regions.json
if [ -f "$here/geo-country.csv.gz" ]; then
	install -m 640 -g xfs-signal "$here/geo-country.csv.gz" /etc/xfs/geo-country.csv.gz
	rm -f "$here/geo-country.csv.gz"
fi
[ -s /etc/xfs/geo-country.csv.gz ] || { echo "missing /etc/xfs/geo-country.csv.gz"; exit 1; }
install -D -m 755 "$here/xfs-signalling" /opt/xfs/xfs-signalling
install -m 644 "$here/xfs-signalling.service" /etc/systemd/system/xfs-signalling.service
command -v restorecon >/dev/null && restorecon -R /opt/xfs /etc/xfs /etc/systemd/system/xfs-signalling.service
systemctl daemon-reload
systemctl enable xfs-signalling

echo "== 4. start"
if [ -s /etc/xfs/tls/fullchain.pem ] && [ -s /etc/xfs/tls/privkey.pem ]; then
	systemctl restart xfs-signalling
	sleep 2
	systemctl --no-pager --lines=5 status xfs-signalling
	curl -sk https://127.0.0.1/healthz; echo
else
	echo "TLS certificate not installed yet (§4); service enabled but not started"
fi
ss -tlnp | grep -E ':(443|9090|80) ' || true
