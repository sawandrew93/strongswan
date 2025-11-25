#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <SERVER_PUBLIC_IP>"
  exit 1
fi
SERVER_IP="$1"
# You can change the VPN clients subnet here:
POOL="10.10.10.0/24"

echo "[+] Writing /etc/ipsec.conf..."
sudo tee /etc/ipsec.conf > /dev/null <<EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=yes

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=$SERVER_IP
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-radius
    rightsourceip=$POOL
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity
    ike = aes256-sha256-modp1024, aes128-sha256-modp1024, aes128-sha1-modp1024, 3des-sha1-modp1024, aes256-sha1-modp1024
    esp = aes256-sha256, aes128-sha256, aes128-sha1, 3des-sha1, aes256-sha1
EOF

#Configuring free-radius for authentication
sudo apt install -y freeradius freeradius-utils
sudo systemctl enable freeradius
sudo systemctl start freeradius

echo "[+] Writing /etc/freeradius/3.0/clients.conf..."
sudo cp /etc/freeradius/3.0/clients.conf /etc/freeradius/3.0/clients.conf.bak
sudo sed -i '/client localhost {/,/^}/c\client strongswan {\n    ipaddr = 127.0.0.1\n    secret = vanguard@929\n    shortname = vpn-server\n}' /etc/freeradius/3.0/clients.conf



# Example users
echo "[+] Writing /etc/freeradius/3.0/users..."
sudo tee -a /etc/freeradius/3.0/users <<EOF
user01 Cleartext-Password := "asd123!@#"
user02 Cleartext-Password := "asd123!@#"
user03 Cleartext-Password := "asd123!@#"
EOF


echo "[+] Making backup and modifying /etc/strongswan.d/charon/eap-radius.conf..."
radius_conf="/etc/strongswan.d/charon/eap-radius.conf"

# Backup
sudo cp "$radius_conf" "${radius_conf}.bak.$(date +%F_%H-%M-%S)"

# Enable accounting
sudo sed -i \
    -e 's/^[[:space:]]*#\?[[:space:]]*accounting *= *.*/    accounting = yes/' \
    "$radius_conf"

# Restart strongswan/charon
sudo systemctl restart strongswan-starter 2>/dev/null || systemctl restart ipsec

echo "RADIUS accounting enabled."


# 2. Replace empty servers block with configured server (with perfect indentation)
sudo sed -i '/^[[:space:]]*servers {/,/^[[:space:]]*}/c\
    servers {\
        strongswan {\
            address = 127.0.0.1\
            secret = vanguard@929\
            auth_port = 1812\
            acct_port = 1813\
        }\
    }' "$radius_conf"


echo "[+] Restarting StrongSwan..."
sudo systemctl restart strongswan-starter.service
sudo systemctl enable strongswan-starter.service
sudo systemctl restart freeradius.service
cat /etc/ipsec.d/cacerts/ca-cert.pem > ca-cert.pem
echo "Copy ca-cert.pem file to your device."
echo "[✔] Setup complete! Your VPN server at $SERVER_IP is ready."
