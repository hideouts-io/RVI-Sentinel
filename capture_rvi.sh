#!/bin/zsh
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./capture_rvi.sh devices
  ./capture_rvi.sh start <UDID>
  ./capture_rvi.sh capture [output.pcapng] [interface]
  ./capture_rvi.sh stop [UDID]
  ./capture_rvi.sh status

Examples:
  ./capture_rvi.sh devices
  ./capture_rvi.sh start 00008110-001234567890001E
  ./capture_rvi.sh capture captures/ios_capture.pcapng
  ./capture_rvi.sh stop 00008110-001234567890001E
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 1
  }
}

find_rvi() {
  ifconfig -l | tr ' ' '\n' | grep -E '^rvi[0-9]+$' | head -n 1 || true
}

cmd="${1:-}"
case "$cmd" in
  devices)
    require_cmd xcrun
    xcrun xctrace list devices
    ;;

  start)
    require_cmd rvictl
    udid="${2:-}"
    [[ -n "$udid" ]] || { usage; exit 2; }
    rvictl -s "$udid"
    sleep 1
    iface="$(find_rvi)"
    if [[ -n "$iface" ]]; then
      echo "RVI ready: $iface"
    else
      echo "rvictl returned but no rvi interface was detected." >&2
      exit 1
    fi
    ;;

  capture)
    require_cmd tcpdump
    output="${2:-captures/ios_capture.pcapng}"
    iface="${3:-$(find_rvi)}"
    [[ -n "$iface" ]] || {
      echo "No RVI interface found. Start one first with: ./capture_rvi.sh start <UDID>" >&2
      exit 1
    }
    mkdir -p "$(dirname "$output")"
    echo "Capturing $iface -> $output"
    echo "Press Ctrl-C to stop."
    sudo tcpdump -i "$iface" -s 0 -U -n -w "$output"
    ;;

  stop)
    require_cmd rvictl
    udid="${2:-}"
    if [[ -n "$udid" ]]; then
      rvictl -x "$udid"
    else
      iface="$(find_rvi)"
      if [[ -n "$iface" ]]; then
        echo "Active interface: $iface"
        echo "Supply the device UDID to stop it:"
        echo "  ./capture_rvi.sh stop <UDID>"
        exit 2
      else
        echo "No RVI interface detected."
      fi
    fi
    ;;

  status)
    iface="$(find_rvi)"
    if [[ -n "$iface" ]]; then
      echo "RVI active: $iface"
      ifconfig "$iface"
    else
      echo "No RVI interface detected."
    fi
    ;;

  *)
    usage
    exit 2
    ;;
esac
