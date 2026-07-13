#!/usr/bin/env bash
set -euo pipefail

server="${1:?server name required}"
useradd --create-home --home-dir /home/testuser --shell /bin/bash testuser
printf 'testuser:testpass\n' | chpasswd
mkdir -p /home/testuser/upload /run/sshd /var/run/vsftpd/empty
chown -R testuser:testuser /home/testuser

case "$server" in
  openssh)
    ssh-keygen -A
    exec /usr/sbin/sshd -D -e -p 2222 \
      -o PasswordAuthentication=yes \
      -o KbdInteractiveAuthentication=no \
      -o PermitRootLogin=no \
      -o UsePAM=no
    ;;
  vsftpd)
    cat >/etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
chroot_local_user=YES
allow_writeable_chroot=YES
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30009
seccomp_sandbox=NO
listen_port=2121
background=YES
EOF
    while true; do
      /usr/sbin/vsftpd /etc/vsftpd.conf
      while pgrep -x vsftpd >/dev/null; do sleep 0.2; done
    done
    ;;
  proftpd)
    cat >/etc/proftpd/proftpd.conf <<'EOF'
ServerName "gmacFTP compatibility fixture"
ServerType standalone
DefaultServer on
UseIPv6 off
Port 2121
Umask 022
MaxInstances 8
RequireValidShell off
AuthOrder mod_auth_unix.c
DefaultRoot ~
PassivePorts 30000 30009
AllowOverwrite on
TransferLog NONE
EOF
    exec /usr/sbin/proftpd --nodaemon --config /etc/proftpd/proftpd.conf
    ;;
  pure-ftpd)
    mkdir -p /var/empty
    if ! id ftp >/dev/null 2>&1; then
      useradd --system --no-create-home --home-dir /var/empty --shell /usr/sbin/nologin ftp
    fi
    /usr/local/sbin/pure-ftpd \
      --bind=0.0.0.0,2121 \
      --login=unix \
      --noanonymous \
      --chrooteveryone \
      --dontresolve \
      --passiveportrange=30000:30009 \
      --pidfile=/var/run/pure-ftpd.pid \
      --daemonize
    for attempt in $(seq 1 40); do
      [ -s /var/run/pure-ftpd.pid ] && break
      sleep 0.05
    done
    [ -s /var/run/pure-ftpd.pid ] || exit 1
    while kill -0 "$(cat /var/run/pure-ftpd.pid)" 2>/dev/null; do sleep 1; done
    exit 1
    ;;
  *)
    printf 'unknown compatibility server: %s\n' "$server" >&2
    exit 64
    ;;
esac
