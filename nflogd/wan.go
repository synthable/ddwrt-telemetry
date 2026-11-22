package main

import "strings"

// parseDefaultRouteIface extracts the egress interface name following "dev"
// from `ip route show default` output (e.g. "default via 203.0.113.1 dev eth0").
func parseDefaultRouteIface(routeOutput string) string {
	for _, line := range strings.Split(routeOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "default" {
			continue
		}
		for i := 1; i < len(fields)-1; i++ {
			if fields[i] == "dev" && fields[i+1] != "" {
				return fields[i+1]
			}
		}
	}
	return ""
}
