#!/bin/sh
# TURN host (Ubuntu): coturn in the official image, IPv4 + IPv6, then self-check.
# See README.md, "Deployment". Re-running is safe (re-renders, restarts).
#
#   scp deploy/turn-host.sh deploy/turnserver.conf deploy/90-xfs.conf bin/linux/xfs-turn-check <host>:xfs-deploy/
#   scp <secret file> <host>:xfs-deploy/turn-secret        # same file as the signalling host's
#   ssh <host> 'sudo PUBLIC_IPV4=<ip> BPS=0 sh xfs-deploy/turn-host.sh'
set -eu
IMAGE=coturn/coturn:4.18.0
here=$(cd "$(dirname "$0")" && pwd)
: "${PUBLIC_IPV4:?set PUBLIC_IPV4}"
BPS=${BPS:-0}
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

echo "== 1. remove what this host does not need"
systemctl disable --now nginx 2>/dev/null || true
DEBIAN_FRONTEND=noninteractive apt-get purge -y -q nginx nginx-common nginx-core 2>/dev/null || true

echo "== 2. system update, Docker (Tencent mirror: Docker Hub is unreliable from the mainland)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get -y -q -o Dpkg::Options::=--force-confold full-upgrade
apt-get install -y -q docker.io
install -d -m 755 /etc/docker
[ -f /etc/docker/daemon.json ] || echo '{"registry-mirrors":["https://mirror.ccs.tencentyun.com"],"log-driver":"journald"}' > /etc/docker/daemon.json
systemctl enable docker
systemctl restart docker
install -m 644 "$here/90-xfs.conf" /etc/sysctl.d/90-xfs.conf
sysctl --system >/dev/null

echo "== 3. secret and configuration"
install -d -m 750 /etc/xfs
if [ -f "$here/turn-secret" ]; then
	install -m 600 "$here/turn-secret" /etc/xfs/turn-secret
	rm -f "$here/turn-secret"
fi
[ -s /etc/xfs/turn-secret ] || { echo "missing /etc/xfs/turn-secret"; exit 1; }
dev=$(ip -4 route show default | awk '{print $5; exit}')
priv4=$(ip -4 -o addr show dev "$dev" scope global | awk '{split($4,a,"/"); print a[1]; exit}')
pub6=$(ip -6 -o addr show dev "$dev" scope global | awk '{split($4,a,"/"); print a[1]}' | grep -v '^f[cd]' | head -1 || true)
echo "device=$dev private4=$priv4 public4=$PUBLIC_IPV4 public6=${pub6:-none}"
secret=$(tr -d ' \r\n' < /etc/xfs/turn-secret)
umask 077
sed -e "s|<PRIVATE_IPV4>|$priv4|g" -e "s|<PUBLIC_IPV4>|$PUBLIC_IPV4|g" \
	-e "s|<same value as /etc/xfs/turn-secret>|$secret|" \
	-e "s|<0.8 x host bandwidth in bytes/s, or 0>|$BPS|" "$here/turnserver.conf" > /etc/xfs/turnserver.conf.new
if [ -n "$pub6" ]; then
	sed -i "s|<PUBLIC_IPV6>|$pub6|g" /etc/xfs/turnserver.conf.new
else
	sed -i '/<PUBLIC_IPV6>/d' /etc/xfs/turnserver.conf.new
fi
! grep -q '<' /etc/xfs/turnserver.conf.new || { echo "unfilled placeholder"; grep -n '<' /etc/xfs/turnserver.conf.new | cut -d= -f1; exit 1; }
# The image runs as nobody: a config it cannot read makes coturn start WITHOUT auth.
chown 65534:65534 /etc/xfs/turnserver.conf.new
chmod 400 /etc/xfs/turnserver.conf.new
mv /etc/xfs/turnserver.conf.new /etc/xfs/turnserver.conf

echo "== 4. coturn $IMAGE"
docker pull -q "$IMAGE"
docker rm -f xfs-coturn 2>/dev/null || true
docker run -d --name xfs-coturn --restart unless-stopped --network host \
	--ulimit nofile=65536:65536 \
	-v /etc/xfs/turnserver.conf:/etc/coturn/turnserver.conf:ro \
	"$IMAGE" -c /etc/coturn/turnserver.conf >/dev/null
sleep 3
docker ps --filter name=xfs-coturn --format '{{.Status}}'
docker logs xfs-coturn 2>&1 | grep -iE 'version|error|unknown|bad|cannot' | head -20 || true

echo "== 5. self-check (must both be OK before the security group opens 3478)"
chk="$here/xfs-turn-check"
rc=0
"$chk" -probe-unauth "$priv4:3478" || rc=1
"$chk" -probe-peers "$priv4:3478" -turn-secret-file /etc/xfs/turn-secret || rc=1
if [ -n "$pub6" ]; then
	"$chk" -probe-unauth "[$pub6]:3478" || rc=1
fi
exit $rc
