#!/bin/sh
# Prepares a server for Key-Box' SSH certificates. Run as root on the server.
#
#   keybox-server-setup.sh fuld   CA.pub [tjeneste ...]
#   keybox-server-setup.sh status CA.pub
#
# "status": the server only ever lets the agent run the read-only overview,
#           whatever certificate it presents. For machines agents should not
#           be able to change, such as the one Key-Box itself runs on.
# "fuld":   overview, error log, security updates, restart of the named
#           services, reboot of the server, and (as a separate user) a full
#           shell for level 3.
#
# The server trusts the CA for the Key-Box users only, never for root or
# anyone else, and never for port, agent or X11 forwarding.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "kør som root" >&2; exit 1; }
MODE="${1:?fuld eller status}"; CA="${2:?sti til CA'ens offentlige nøgle}"; shift 2
case "$MODE" in fuld|status) ;; *) echo "første argument skal være fuld eller status" >&2; exit 1 ;; esac
HERE=$(cd "$(dirname "$0")" && pwd)
ssh-keygen -l -f "$CA" >/dev/null || { echo "$CA er ikke en offentlig SSH-nøgle" >&2; exit 1; }

id keybox-agent >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/keybox-agent --shell /bin/sh keybox-agent
install -d -m 0755 -o root -g root /usr/local/lib/keybox /etc/keybox-agent
install -m 0755 -o root -g root "$HERE/status" /usr/local/lib/keybox/status
install -m 0644 -o root -g root "$CA" /etc/ssh/keybox_ca.pub

CONF=/etc/ssh/sshd_config.d/50-keybox.conf
if [ "$MODE" = status ]; then
    rm -f /usr/local/lib/keybox/logs /usr/local/lib/keybox/opdater /usr/local/lib/keybox/genstart /usr/local/lib/keybox/genstart-server /etc/sudoers.d/keybox-agent
    cat > "$CONF" <<'CONF'
# Key-Box: agenten kan kun køre den skrivebeskyttede oversigt på denne server.
# ForceCommand her gælder uanset, hvad certifikatet siger.
Match User keybox-agent
    TrustedUserCAKeys /etc/ssh/keybox_ca.pub
    AuthorizedKeysFile none
    ForceCommand /usr/local/lib/keybox/status
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
CONF
else
    install -m 0755 -o root -g root "$HERE/logs" "$HERE/opdater" "$HERE/genstart" "$HERE/genstart-server" /usr/local/lib/keybox/
    : > /etc/keybox-agent/tjenester.new
    for t in "$@"; do
        case "$t" in *[!a-zA-Z0-9@._:-]*|"") echo "ugyldigt tjenestenavn: $t" >&2; exit 1 ;; esac
        printf '%s\n' "$t" >> /etc/keybox-agent/tjenester.new
    done
    install -m 0644 -o root -g root /etc/keybox-agent/tjenester.new /etc/keybox-agent/tjenester; rm /etc/keybox-agent/tjenester.new
    id keybox-admin >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/keybox-admin --shell /bin/bash keybox-admin
    # keybox-agent: four fixed commands as root, nothing else. "genstart"
    # checks its argument itself against /etc/keybox-agent/tjenester.
    # keybox-admin: everything. Only reachable with a level 3 certificate.
    cat > /etc/sudoers.d/keybox-agent.new <<'SUDO'
keybox-agent ALL=(root) NOPASSWD: /usr/local/lib/keybox/logs ""
keybox-agent ALL=(root) NOPASSWD: /usr/local/lib/keybox/opdater ""
keybox-agent ALL=(root) NOPASSWD: /usr/local/lib/keybox/genstart *
keybox-agent ALL=(root) NOPASSWD: /usr/local/lib/keybox/genstart-server ""
keybox-admin ALL=(ALL:ALL) NOPASSWD: ALL
SUDO
    visudo -c -q -f /etc/sudoers.d/keybox-agent.new
    install -m 0440 -o root -g root /etc/sudoers.d/keybox-agent.new /etc/sudoers.d/keybox-agent; rm /etc/sudoers.d/keybox-agent.new
    cat > "$CONF" <<'CONF'
# Key-Box: certifikater fra Key-Box' CA gælder kun for disse to brugere.
# keybox-agent kører faste kommandoer (certifikatet låser hvilken).
# keybox-admin er fuld adgang og kræver niveau 3 i Key-Box.
Match User keybox-agent,keybox-admin
    TrustedUserCAKeys /etc/ssh/keybox_ca.pub
    AuthorizedKeysFile none
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
CONF
fi
chmod 0644 "$CONF"
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd
echo "Klar ($MODE). CA: $(ssh-keygen -l -f /etc/ssh/keybox_ca.pub | awk '{print $2}')"
echo "root stoler på CA'en: $(sshd -T -C user=root,host=x,addr=127.0.0.1 | awk '/^trustedusercakeys/ {print $2}')"
echo "keybox-agent:         $(sshd -T -C user=keybox-agent,host=x,addr=127.0.0.1 | awk '/^trustedusercakeys/ {print $2}')"
