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

echo "tun0 IP: $TUN0_IP" | tee $OUTPUT_DIR/TUN0_IP

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

echo "PIA_TOKEN=$TOKEN" | tee $OUTPUT_DIR/token

######################################################################################
# PART 2 - get the port configured
######################################################################################
TUN0_GW=$(ip route show dev tun0 | awk '/via/ {print $3; exit}')
echo "tun0 Gateway: $TUN0_GW" |

# get the payload
echo "Getting payload and signature..."
PAYLOAD_AND_SIG=$(curl -s -k "https://$TUN0_GW:19999/getSignature?token=$TOKEN")

if [ -z "$PAYLOAD_AND_SIG" ]; then
    echo "Error: Could not retrieve payload and signature from $TUN0_GW:19999."
    exit 1
fi

PAYLOAD=$(echo "$PAYLOAD_AND_SIG" | jq -r '.payload')
SIGNATURE=$(echo "$PAYLOAD_AND_SIG" | jq -r '.signature')

echo "PAYLOAD=$PAYLOAD" | tee $OUTPUT_DIR/PAYLOAD
echo "SIGNATURE=$SIGNATURE" | tee $OUTPUT_DIR/SIGNATURE


if [ -z "$PAYLOAD" ] || [ "$PAYLOAD" == "null" ]; then
    echo "Error: Could not extract PAYLOAD. Response: $PAYLOAD_AND_SIG" | tee $OUTPUT_DIR/ERROR
    exit 1
fi

if [ -z "$SIGNATURE" ] || [ "$SIGNATURE" == "null" ]; then
    echo "Error: Could not extract SIGNATURE. Response: $PAYLOAD_AND_SIG" | tee $OUTPUT_DIR/ERROR
    exit 1
fi

# Bind the port over the VPN
echo "Binding port over the VPN..."
BIND_RESPONSE=$(curl -sGk --data-urlencode "payload=${PAYLOAD}" --data-urlencode "signature=${SIGNATURE}" "https://$TUN0_GW:19999/bindPort")
echo "Bind Port Response: $BIND_RESPONSE" | tee $OUTPUT_DIR/bind_port_response

# capture the assigned port
echo "Decoding payload and extracting assigned port..."
BINDPORT=$(echo "$PAYLOAD" | base64 -d | jq -r '.port')

if [ -z "$BINDPORT" ] || [ "$BINDPORT" == "null" ]; then
    echo "Error: Could not extract BINDPORT from payload. Payload: $PAYLOAD" | tee $OUTPUT_DIR/ERROR
    exit 1
fi

echo "Assigned Port: $BINDPORT" | tee $OUTPUT_DIR/PORT


######################################################################################
# PART 3 - update transmission
######################################################################################
systemctl stop transmission-daemon

jq --arg ip "${TUN0_IP}" '.["bind-address-ipv4"] = $ip' /var/lib/transmission/.config/transmission-daemon/settings.json | sponge /var/lib/transmission/.config/transmission-daemon/settings.json

jq --arg ip "${TUN0_IP}" --argjson port "$BINDPORT" \
   '.["bind-address-ipv4"] = $ip
    | .["peer-port"] = $port
    | .["peer-port-random-on-start"] = false' \
   /var/lib/transmission/.config/transmission-daemon/settings.json | sponge /var/lib/transmission/.config/transmission-daemon/settings.json

chown transmission:transmission /var/lib/transmission/.config/transmission-daemon/settings.json

systemctl start transmission-daemon


######################################################################################
# PART 4 - keep refreshing the portbind
######################################################################################
while true; do
        PORT_REFRESH=$(curl -sGk --data-urlencode "payload=${PAYLOAD}" --data-urlencode "signature=${SIGNATURE}" "https://$TUN0_GW:19999/bindPort")

        printf "%s\nVPN_IP=%s\nPORT=%s\nRefreshing...:\n%s\n" \
            "$(date +%Y-%m-%d@%H:%M:%S)" \
            "${TUN0_IP}" \
            "${BINDPORT}" \
            "${PORT_REFRESH}" \
            >> /var/log/pia_refresh.log

        sleep 890 # refresh every 15 minutes
done
