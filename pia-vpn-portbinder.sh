#!/usr/bin/env bash


PIA_USER=SOMEUSER
PIA_PASS='SOMEPASS'

OUTPUT_DIR=/opt/piavpn-manual
######################################################################################
# PART 0 - connect the VPN
######################################################################################

echo "Starting OpenVPN client..."
systemctl start openvpn-client@client.service

# Wait for tun0 interface to come up and get an IP
echo "Waiting for tun0 interface to be up..."
attempts=0
max_attempts=30 # Adjust as needed (e.g., 30 seconds)
while [ -z "$TUN0_IP" ] && [ $attempts -lt $max_attempts ]; do
    sleep 1
    TUN0_IP="$(ip addr | awk '/inet/ && /tun0/ { ip = $2; sub(/\/.*/, "", ip); print ip }')"
    attempts=$((attempts+1))
done

if [ -z "$TUN0_IP" ]; then
    echo "Error: tun0 interface not up or no IP address assigned after $max_attempts seconds."
    exit 1
fi

echo "tun0 IP: $TUN0_IP"

######################################################################################
# PART 1 - GET TOKEN
######################################################################################

mkdir -p $OUTPUT_DIR

echo "Generating tokens from PIA_USER and PIA_PASS..."
generateTokenResponse=$(curl -s --location --request POST \
  'https://www.privateinternetaccess.com/api/client/v2/token' \
  --form "username=$PIA_USER" \
  --form "password=$PIA_PASS" )

TOKEN=$(echo "$generateTokenResponse" | jq -r '.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    echo "Error: Could not retrieve PIA_TOKEN. Response: $generateTokenResponse"
    exit 1
fi

echo "PIA_TOKEN=$TOKEN" > $OUTPUT_DIR/token
echo "Token successfully retrieved and saved."

######################################################################################
# PART 2 - get the port configured
######################################################################################
# get the tun0 gw (always .1)
TUN0_GW="${TUN0_IP%.*}.1"
echo "tun0 Gateway: $TUN0_GW"

# get the payload
echo "Getting payload and signature..."
PAYLOAD_AND_SIG=$(curl -s -k "https://$TUN0_GW:19999/getSignature?token=$TOKEN")

if [ -z "$PAYLOAD_AND_SIG" ]; then
    echo "Error: Could not retrieve payload and signature from $TUN0_GW:19999."
    exit 1
fi

PAYLOAD=$(echo "$PAYLOAD_AND_SIG" | jq -r '.payload')
SIGNATURE=$(echo "$PAYLOAD_AND_SIG" | jq -r '.signature')

if [ -z "$PAYLOAD" ] || [ "$PAYLOAD" == "null" ]; then
    echo "Error: Could not extract PAYLOAD. Response: $PAYLOAD_AND_SIG"
    exit 1
fi

if [ -z "$SIGNATURE" ] || [ "$SIGNATURE" == "null" ]; then
    echo "Error: Could not extract SIGNATURE. Response: $PAYLOAD_AND_SIG"
    exit 1
fi

# Bind the port over the VPN
echo "Binding port over the VPN..."
BIND_RESPONSE=$(curl -sGk --data-urlencode "payload=${PAYLOAD}" --data-urlencode "signature=${SIGNATURE}" "https://$TUN0_GW:19999/bindPort")
echo "Bind Port Response: $BIND_RESPONSE"

# capture the assigned port
echo "Decoding payload and extracting assigned port..."
BINDPORT=$(echo "$PAYLOAD" | base64 -d | jq -r '.port')

if [ -z "$BINDPORT" ] || [ "$BINDPORT" == "null" ]; then
    echo "Error: Could not extract BINDPORT from payload. Payload: $PAYLOAD"
    exit 1
fi

echo "Assigned Port: $BINDPORT" > $OUTPUT_DIR/PORT


######################################################################################
# PART 3 - update transmission
######################################################################################
systemctl stop transmission-daemon

jq --arg ip "${TUN0_IP}" '.["bind-address-ipv4"] = $ip' /var/lib/transmission/.config/transmission-daemon/settings.json | sponge /var/lib/transmission/.config/transmission-daemon/settings.json

chown transmission:transmission /var/lib/transmission/.config/transmission-daemon/settings.json

systemctl start transmission-daemon


######################################################################################
# PART 4 - keep refreshing the portbind
######################################################################################
while true; do
        curl -sGk --data-urlencode "payload=${PAYLOAD}" --data-urlencode "signature=${SIGNATURE}" "https://$TUN0_GW:19999/bindPort" > /root/pia_refresh.log
        sleep 600
done
