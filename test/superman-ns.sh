# Max 54 nodes
NUM_NODES=10
NS_PREPEND=node-
MAIN_ETH=eth0
IP_PREFIX=10.0.0.
BRIDGE_NAME=${NS_PREPEND}br
BRIDGE_IP=${IP_PREFIX}1

function NS_Setup() {

	# Set up the network bridge for the NS connections
	brctl addbr ${BRIDGE_NAME}
	brctl stp ${BRIDGE_NAME} off
	ip addr add ${BRIDGE_IP}/24 brd + dev ${BRIDGE_NAME}
	ip link set dev ${BRIDGE_NAME} up
	#brctl addif ${BRIDGE_NAME} ${MAIN_ETH}

	# Share internet access between host and NS.

	# Enable IP-forwarding.
	echo 1 > /proc/sys/net/ipv4/ip_forward

	# Flush forward rules, policy DROP by default.
	iptables -P FORWARD DROP
	iptables -F FORWARD

	# Flush nat rules.
	iptables -t nat -F

	# Enable masquerading
	iptables -t nat -A POSTROUTING -s ${IP_PREFIX}0/255.255.255.0 -o ${MAIN_ETH} -j MASQUERADE
	iptables -A FORWARD -i ${BRIDGE_NAME} -o ${MAIN_ETH} -j ACCEPT

	# Permit free flowing traffic on the bridge
	iptables -A INPUT -i ${BRIDGE_NAME} -j ACCEPT
	iptables -A OUTPUT -o ${BRIDGE_NAME} -j ACCEPT

	# Create namespaces
	for NODEID in $(seq 1 ${NUM_NODES}); do

		NS_NAME=${NS_PREPEND}${NODEID}
		VETH=veth-${NODEID}
		VPEER=vpeer-${NODEID}
		VETH_IP=${IP_PREFIX}$((100 + ${NODEID}))
		VPEER_IP=${IP_PREFIX}$((200 + ${NODEID}))

		echo -e "Setting up node ${NODEID}..."
		ip netns add ${NS_NAME}

		# Create veth link.
		ip link add ${VETH} type veth peer name ${VPEER}

		# Add veth to the bridge
		brctl addif ${BRIDGE_NAME} ${VETH}

		# Add peer-1 to NS.
		ip link set ${VPEER} netns ${NS_NAME}

		# Setup IP address of veth.
		ip addr add ${VETH_IP}/24 brd + dev ${VETH}
		ip link set ${VETH} up

		# Setup IP address of vpeer.
		ip netns exec ${NS_NAME} ip addr add ${VPEER_IP}/24 brd + dev ${VPEER}
		ip netns exec ${NS_NAME} ip link set ${VPEER} up
		ip netns exec ${NS_NAME} ip link set lo up

		# Add a default route for NS traffic to exit via
		#ip netns exec ${NS_NAME} ip route add default via ${ETH_IP}
		ip netns exec ${NS_NAME} ip route add default via ${BRIDGE_IP}

		# Allow forwarding between the main eth and veth.
		iptables -A FORWARD -i ${MAIN_ETH} -o ${VETH} -j ACCEPT
		iptables -A FORWARD -o ${MAIN_ETH} -i ${VETH} -j ACCEPT

	done

}

function NS_Destroy() {

	iptables -F FORWARD
	iptables -F -t nat

	# Create namespaces
	for NODEID in $(seq 1 ${NUM_NODES}); do

		NS_NAME=${NS_PREPEND}${NODEID}

		# Remove namespace if it exists.
		ip netns del ${NS_NAME} &>/dev/null

	done

	ip link set dev ${BRIDGE_NAME} down
	brctl delbr ${BRIDGE_NAME}

}

function NS_Run() {

	if [ $# -eq 0 ]; then
		echo -e "Usage: RunNS {node id} {command} {args}"
	else
		# Perform some sanity checks before running the command
		if [ "$1" -ge 0 -a "$1" -le ${NUM_NODES} ] 2>/dev/null ; then
			echo ip netns exec ${NS_PREPEND}${@}
			ip netns exec ${NS_PREPEND}${@}
		else
			echo "Invalid node id: $1"
		fi
	fi
}

function NS_Term() {

	if [ $# -eq 0 ]; then
		echo -e "Usage: RunTerm {node id}"
	else
		# Perform some sanity checks before running the command
		if [ "$1" -ge 0 -a "$1" -le ${NUM_NODES} ] 2>/dev/null ; then
			echo ip netns exec ${NS_PREPEND}${1} gnome-terminal -x bash
			ip netns exec ${NS_PREPEND}${1} gnome-terminal -x bash
		else
			echo "Invalid node id: $1"
		fi
	fi
}

function NS_RunAll() {

	if [ $# -eq 0 ]; then
		echo -e "Usage: RunAll {command} {args}"
	else
		# Create namespaces
		for NODEID in $(seq 1 ${NUM_NODES}); do

			NS_NAME=${NS_PREPEND}${NODEID}

			# Remove namespace if it exists.
			echo ip netns exec ${NS_NAME} ${@}
			ip netns exec ${NS_NAME} ${@}

		done
	fi
}




#SetupTestNS
#DestroyTestNS

