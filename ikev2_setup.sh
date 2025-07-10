#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <SERVER_PUBLIC_IP>"
  exit 1
fi
SERVER_IP="$1"
# You can change the VPN clients subnet here:
POOL="10.10.10.0/24"

echo "[+] Updating and installing StrongSwan..."
sudo apt update
sudo apt install -y strongswan strongswan-pki \
  libcharon-extra-plugins libcharon-extauth-plugins \
  libstrongswan-extra-plugins

sudo apt install -y libtss2-tcti-tabrmd0

echo "[+] Setting up PKI dirs..."
PKI=~/pki
mkdir -p "$PKI"/{cacerts,certs,private}
chmod 700 "$PKI"

echo "[+] Generating CA key and cert..."
pki --gen --type rsa --size 4096 --outform pem > "$PKI"/private/ca-key.pem
pki --self --ca --lifetime 3650 \
  --in "$PKI"/private/ca-key.pem \
  --type rsa --dn "CN=VPN$1 root CA" \
  --outform pem > "$PKI"/cacerts/ca-cert.pem

echo "[+] Generating server key and cert..."
pki --gen --type rsa --size 4096 --outform pem > "$PKI"/private/server-key.pem
pki --pub --in "$PKI"/private/server-key.pem --type rsa \
  | pki --issue --lifetime 1825 \
    --cacert "$PKI"/cacerts/ca-cert.pem \
    --cakey "$PKI"/private/ca-key.pem \
    --dn "CN=$SERVER_IP" --san "$SERVER_IP" \
    --flag serverAuth --flag ikeIntermediate \
    --outform pem > "$PKI"/certs/server-cert.pem

echo "[+] Deploying certs..."
sudo cp -r "$PKI"/* /etc/ipsec.d/

echo "[+] Writing /etc/ipsec.conf..."
sudo tee /etc/ipsec.conf > /dev/null <<EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

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
    rightauth=eap-mschapv2
    rightsourceip=$POOL
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity
    ike = aes256-sha256-modp1024, aes128-sha256-modp1024, aes128-sha1-modp1024, 3des-sha1-modp1024, aes256-sha1-modp1024
    esp = aes256-sha256, aes128-sha256, aes128-sha1, 3des-sha1, aes256-sha1
EOF

echo "[+] Writing /etc/ipsec.secrets..."
sudo tee /etc/ipsec.secrets > /dev/null <<EOF
: RSA "server-key.pem"
# Add users in format: username : EAP "password"
mi11 : EAP "asd123!@#"
user01 : EAP "asd123!@#"
EOF

echo "[+] Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf

echo "[+] Configuring UFW for NAT and VPN ports..."
IFACE=$(ip route show default | awk '{print $5}')
sudo ufw allow OpenSSH
sudo ufw allow 500,4500/udp

sudo tee /etc/ufw/before.rules > /dev/null <<EOF
# rules.before
#
# Rules that should be run before the ufw command line added rules. Custom
# rules should be added to one of these chains:
#   ufw-before-input
#   ufw-before-output
#   ufw-before-forward
#
*nat
:POSTROUTING ACCEPT [0:0]

# Forward VPN traffic through eth0
-A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE

COMMIT

*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]

# Allow IPsec traffic
-A ufw-before-forward --match policy --pol ipsec --dir in --proto esp -s 10.10.10.0/24 -j ACCEPT
-A ufw-before-forward --match policy --pol ipsec --dir out --proto esp -d 10.10.10.0/24 -j ACCEPT

# allow all on loopback
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT

# quickly process packets for which we already have a connection
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# drop INVALID packets (logs these in loglevel medium and higher)
-A ufw-before-input -m conntrack --ctstate INVALID -j ufw-logging-deny
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP

# ok icmp codes for INPUT
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT

# ok icmp code for FORWARD
-A ufw-before-forward -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT

# allow dhcp client to work
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT

#
# ufw-not-local
#
-A ufw-before-input -j ufw-not-local

# if LOCAL, RETURN
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN

# if MULTICAST, RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN

# if BROADCAST, RETURN
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN

# all other non-local packets are dropped
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny
-A ufw-not-local -j DROP

# allow MULTICAST mDNS for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT

# allow MULTICAST UPnP for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT

# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
EOF

echo "[+] Reloading UFW..."
sudo ufw disable
sudo ufw enable

echo "[+] Restarting StrongSwan..."
sudo systemctl restart strongswan-starter.service
sudo systemctl enable strongswan-starter.service

echo "[✔] Setup complete! Your VPN server at $SERVER_IP is ready."
