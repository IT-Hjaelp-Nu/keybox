#!/bin/sh
# Installs the Key-Box client for the user "hermes". Run with sudo.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" -eq 0 ] || { echo "kør med sudo" >&2; exit 1; }
install -m 0755 -o root -g root "$HERE/keyboxd" /usr/local/bin/keyboxd
install -m 0755 -o root -g root "$HERE/keybox" /usr/local/bin/keybox
install -d -m 0700 -o hermes -g hermes /home/hermes/.keybox
# The key is only in the package the first time; later runs just update the rest.
if [ -f "$HERE/hermes.key" ]; then
    install -m 0600 -o hermes -g hermes "$HERE/hermes.key" /home/hermes/.keybox/
fi
install -m 0600 -o hermes -g hermes "$HERE/hermes.pem" "$HERE/agent-ca.pem" /home/hermes/.keybox/
install -m 0644 -o hermes -g hermes "$HERE/KEYBOX.md" /home/hermes/.keybox/KEYBOX.md
# No copy of the private key is left outside hermes' own directory.
rm -f "$HERE/hermes.key"
echo "Installeret. Prøver forbindelsen som hermes:"
sudo -u hermes -H /usr/local/bin/keybox '{"op":"status","id":"00000000000000000000000000000000"}' || echo "Ingen forbindelse endnu (er Tailscale oppe?)"
