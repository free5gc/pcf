package util

import (
	"fmt"
	"math/big"
	"net/netip"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/flowdesc"
)

type trafficInterval struct{ low, high *big.Int }

// The dimensions are IP family, source/destination address, protocol,
// source/destination port and direction. Coverage checks operate on sets so two
// adjacent request filters can together cover an entire existing service filter.
type trafficRegion [7]trafficInterval

func trafficInfluenceCovered(inner, outer []models.Pcf_SMPolCtrl_FlowInformation, assigned []string) (bool, error) {
	for _, flow := range inner {
		remaining, err := trafficRegions(flow, assigned)
		if err != nil {
			return false, err
		}
		for _, filter := range outer {
			// A restricted service filter cannot prove coverage of unrestricted traffic.
			if (filter.TosTrafficClass != "" && filter.TosTrafficClass != flow.TosTrafficClass) ||
				(filter.Spi != "" && filter.Spi != flow.Spi) ||
				(filter.FlowLabel != "" && filter.FlowLabel != flow.FlowLabel) {
				continue
			}
			regions, err := trafficRegions(filter, assigned)
			if err != nil {
				return false, err
			}
			for _, covered := range regions {
				var next []trafficRegion
				for _, region := range remaining {
					next = append(next, subtractTrafficRegion(region, covered)...)
				}
				remaining = next
			}
			if len(remaining) == 0 {
				break
			}
		}
		if len(remaining) != 0 {
			return false, nil
		}
	}
	return true, nil
}

func trafficRegions(info models.Pcf_SMPolCtrl_FlowInformation, assigned []string) ([]trafficRegion, error) {
	if info.EthFlowDescription != nil {
		return nil, fmt.Errorf("ethernet TI coverage is not supported")
	}
	filter, err := strictIPFilter(info.FlowDescription)
	if err != nil {
		return nil, err
	}
	sources, err := trafficPrefixes(filter.Src, assigned)
	if err != nil {
		return nil, err
	}
	destinations, err := trafficPrefixes(filter.Dst, assigned)
	if err != nil {
		return nil, err
	}
	ports := func(ranges flowdesc.PortRanges) []trafficInterval {
		if len(ranges) == 0 {
			return []trafficInterval{numericTrafficInterval(0, 65535)}
		}
		var result []trafficInterval
		for _, port := range ranges {
			result = append(result, numericTrafficInterval(int64(port.Start), int64(port.End)))
		}
		return result
	}
	protocol := numericTrafficInterval(int64(filter.Proto), int64(filter.Proto))
	if filter.Proto == flowdesc.ProtocolNumberAny {
		protocol = numericTrafficInterval(0, 255)
	}
	direction := numericTrafficInterval(1, 2)
	switch info.FlowDirection {
	case models.Pcf_SMPolCtrl_FlowDirectionRm_DOWNLINK:
		direction = numericTrafficInterval(1, 1)
	case models.Pcf_SMPolCtrl_FlowDirectionRm_UPLINK:
		direction = numericTrafficInterval(2, 2)
	case "", models.Pcf_SMPolCtrl_FlowDirectionRm_BIDIRECTIONAL:
	default:
		return nil, fmt.Errorf("unsupported TI flow direction %s", info.FlowDirection)
	}
	var result []trafficRegion
	for _, source := range sources {
		for _, destination := range destinations {
			if source.Addr().Is4() != destination.Addr().Is4() {
				continue
			}
			family := int64(6)
			if source.Addr().Is4() {
				family = 4
			}
			for _, sourcePort := range ports(filter.SrcPorts) {
				for _, destinationPort := range ports(filter.DstPorts) {
					result = append(result, trafficRegion{
						numericTrafficInterval(family, family),
						prefixTrafficInterval(source), prefixTrafficInterval(destination), protocol,
						sourcePort, destinationPort, direction,
					})
				}
			}
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no applicable address family for TI filter %s", info.FlowDescription)
	}
	return result, nil
}

func trafficPrefixes(value string, assigned []string) ([]netip.Prefix, error) {
	if value == "any" {
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}, nil
	}
	values := []string{value}
	if value == "assigned" {
		values = assigned
	}
	var result []netip.Prefix
	for _, candidate := range values {
		if candidate == "" {
			continue
		}
		if address, err := netip.ParseAddr(candidate); err == nil {
			result = append(result, netip.PrefixFrom(address, address.BitLen()))
		} else if prefix, err := netip.ParsePrefix(candidate); err == nil {
			result = append(result, prefix.Masked())
		} else {
			return nil, fmt.Errorf("cannot resolve TI address %q", candidate)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("missing assigned UE address for TI coverage")
	}
	return result, nil
}

func numericTrafficInterval(low, high int64) trafficInterval {
	return trafficInterval{big.NewInt(low), big.NewInt(high)}
}

func prefixTrafficInterval(prefix netip.Prefix) trafficInterval {
	address := prefix.Masked().Addr().As16()
	low := new(big.Int).SetBytes(address[:])
	size := new(big.Int).Lsh(big.NewInt(1), uint(prefix.Addr().BitLen()-prefix.Bits()))
	high := new(big.Int).Sub(new(big.Int).Add(low, size), big.NewInt(1))
	return trafficInterval{low, high}
}

func subtractTrafficRegion(region, covered trafficRegion) []trafficRegion {
	var overlap trafficRegion
	for axis, interval := range region {
		low, high := interval.low, interval.high
		if covered[axis].low.Cmp(low) > 0 {
			low = covered[axis].low
		}
		if covered[axis].high.Cmp(high) < 0 {
			high = covered[axis].high
		}
		if low.Cmp(high) > 0 {
			return []trafficRegion{region}
		}
		overlap[axis] = trafficInterval{low, high}
	}
	var result []trafficRegion
	for axis, intersection := range overlap {
		if region[axis].low.Cmp(intersection.low) < 0 {
			piece := region
			piece[axis].high = new(big.Int).Sub(intersection.low, big.NewInt(1))
			result = append(result, piece)
			region[axis].low = intersection.low
		}
		if region[axis].high.Cmp(intersection.high) > 0 {
			piece := region
			piece[axis].low = new(big.Int).Add(intersection.high, big.NewInt(1))
			result = append(result, piece)
			region[axis].high = intersection.high
		}
	}
	return result
}
