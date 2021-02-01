#!/bin/sh -e

require_osmo_interact_vty() {
	if command -v osmo_interact_vty.py >/dev/null 2>&1; then
		return
	fi
	echo "ERROR: osmo_interact_vty.py not found. Are osmo-python-tests in PATH?"
	exit 1
}

# $1: "update_vty_reference" or "update_counters"
# $2: output file
# $3: port
# $4-$n: command
interact_vty() {
	action="$1"
	output="$2"
	port="$3"
	log="/tmp/$4.log"
	shift 3

	echo "Starting in background: $@"
	"$@" > "$log" 2>&1 &
	pid="$!"

	sleep 0.5
	if ! kill -0 "$pid" 2>/dev/null; then
		echo "ERROR: start failed!"
		cat "$log"
		exit 1
	fi

	case "$action" in
		"update_vty_reference")
			echo "Updating VTY reference: $output"
			osmo_interact_vty.py -X -p "$port" -H 127.0.0.1 -O "$output"
			;;
		"update_counters")
			echo "Updating asciidoc counters: $output"
			osmo_interact_vty.py -c "enable;show asciidoc counters" -p "$port" -H 127.0.0.1 -O "$output"
			;;
		*)
			echo "ERROR: invalid argument: $action"
			exit 1
			;;
	esac

	kill "$pid"
	echo "Done (killed $1)"
	echo
}

DIR="$(cd "$(dirname "$0")"; pwd)"
cd "$DIR"

require_osmo_interact_vty

interact_vty \
	"update_vty_reference" \
	"vty/sgsn_vty_reference.xml" \
	4245 \
	osmo-sgsn -c "../examples/osmo-sgsn/osmo-sgsn.cfg"

interact_vty \
	"update_counters" \
	"chapters/counters_generated.adoc" \
	4245 \
	osmo-sgsn -c "../examples/osmo-sgsn/osmo-sgsn.cfg"


echo "Done with all"
