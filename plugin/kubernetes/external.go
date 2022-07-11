package kubernetes

import (
	"strings"

	"github.com/coredns/coredns/plugin/etcd/msg"
	"github.com/coredns/coredns/plugin/kubernetes/object"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// External implements the ExternalFunc call from the external plugin.
// It returns any services matching in the services' ExternalIPs and if enabled, headless endpoints.
func (k *Kubernetes) External(state request.Request, headless bool) ([]msg.Service, int) {
	base, _ := dnsutil.TrimZone(state.Name(), state.Zone)

	segs := dns.SplitDomainName(base)
	last := len(segs) - 1
	if last < 0 {
		return nil, dns.RcodeServerFailure
	}
	// We are dealing with a fairly normal domain name here, but we still need to have the service
	// and the namespace:
	// service.namespace.<base>
	var port, protocol, endpoint string
	namespace := segs[last]
	if !k.namespaceExposed(namespace) {
		return nil, dns.RcodeNameError
	}

	last--
	if last < 0 {
		return nil, dns.RcodeSuccess
	}

	service := segs[last]
	last--
	if last == 0 {
		endpoint = stripUnderscore(segs[last])
		last--
	} else if last == 1 {
		protocol = stripUnderscore(segs[last])
		port = stripUnderscore(segs[last-1])
		last -= 2
	}

	if last != -1 {
		// too long
		return nil, dns.RcodeNameError
	}

	var (
		endpointsListFunc func() []*object.Endpoints
		endpointsList     []*object.Endpoints
		serviceList       []*object.Service
	)

	idx := object.ServiceKey(service, namespace)
	serviceList = k.APIConn.SvcIndex(idx)
	endpointsListFunc = func() []*object.Endpoints { return k.APIConn.EpIndex(idx) }

	services := []msg.Service{}
	zonePath := msg.Path(state.Zone, coredns)
	rcode := dns.RcodeNameError

	for _, svc := range serviceList {
		if namespace != svc.Namespace {
			continue
		}
		if service != svc.Name {
			continue
		}

		if svc.Headless() || endpoint != "" {
			if endpointsList == nil {
				endpointsList = endpointsListFunc()
			}
			// Endpoint query or headless service
			for _, ep := range endpointsList {
				if object.EndpointsKey(svc.Name, svc.Namespace) != ep.Index {
					continue
				}

				for _, eps := range ep.Subsets {
					for _, addr := range eps.Addresses {

						// See comments in parse.go parseRequest about the endpoint handling.
						if endpoint != "" {
							if !match(endpoint, endpointHostname(addr, k.endpointNameMode)) {
								continue
							}
						}

						for _, p := range eps.Ports {
							if !(matchPortAndProtocol(port, p.Name, protocol, p.Protocol)) {
								continue
							}
							s := msg.Service{Host: addr.IP, Port: int(p.Port), TTL: k.ttl}
							s.Key = strings.Join([]string{zonePath, svc.Namespace, svc.Name, endpointHostname(addr, k.endpointNameMode)}, "/")

							services = append(services, s)
						}
					}
				}
			}
			continue
		} else {

			for _, ip := range svc.ExternalIPs {
				for _, p := range svc.Ports {
					if !(matchPortAndProtocol(port, p.Name, protocol, string(p.Protocol))) {
						continue
					}
					rcode = dns.RcodeSuccess
					s := msg.Service{Host: ip, Port: int(p.Port), TTL: k.ttl}
					s.Key = strings.Join([]string{zonePath, svc.Namespace, svc.Name}, "/")

					services = append(services, s)
				}
			}
		}
	}
	return services, rcode
}

// ExternalAddress returns the external service address(es) for the CoreDNS service.
func (k *Kubernetes) ExternalAddress(state request.Request, headless bool) []dns.RR {
	// If CoreDNS is running inside the Kubernetes cluster: k.nsAddrs() will return the external IPs of the services
	// targeting the CoreDNS Pod.
	// If CoreDNS is running outside of the Kubernetes cluster: k.nsAddrs() will return the first non-loopback IP
	// address seen on the local system it is running on. This could be the wrong answer if coredns is using the *bind*
	// plugin to bind to a different IP address.
	return k.nsAddrs(true, headless,  state.Zone)
}

// ExternalServices returns all services with external IPs and if enabled headless services
func (k *Kubernetes) ExternalServices(zone string, headless bool) (services []msg.Service) {
	zonePath := msg.Path(zone, coredns)
	for _, svc := range k.APIConn.ServiceList() {
		// Endpoint query or headless service
		if headless && svc.Headless() {
			
			idx := object.ServiceKey(svc.Name, svc.Namespace)
		    endpointsList :=  k.APIConn.EpIndex(idx)
	
			for _, ep := range endpointsList {
				if ep.Name != svc.Name || ep.Namespace != svc.Namespace {
					continue
				}

				for _, eps := range ep.Subsets {
					
					for _, addr := range eps.Addresses {

						for _, p := range eps.Ports {
							s := msg.Service{Host: addr.IP, Port: int(p.Port), TTL: k.ttl}
							baseSvc := strings.Join([]string{zonePath, svc.Namespace, svc.Name}, "/")
							s.Key = strings.Join([]string{baseSvc, endpointHostname(addr, k.endpointNameMode)}, "/")
							s.TargetStrip = 0
							s.Group = baseSvc
							services = append(services, s)


							s = msg.Service{Host: addr.IP, Port: int(p.Port), TTL: k.ttl}
							s.Key = strings.Join([]string{baseSvc, endpointHostname(addr, k.endpointNameMode)}, "/")
							s.TargetStrip = 0
							s.Group = baseSvc
							services = append(services, s)

							// s.Key = strings.Join(append([]string{baseSvc, strings.ToLower("_"+string(p.Protocol))}, strings.ToLower("_"+string(p.Name))), "/")
							// s.TargetStrip = 2
							// s.Group = baseSvc
							// services = append(services, s)
						}
					}
				}
			}
			continue
		} else {
			for _, ip := range svc.ExternalIPs {
				for _, p := range svc.Ports {
					s := msg.Service{Host: ip, Port: int(p.Port), TTL: k.ttl}
					s.Key = strings.Join([]string{zonePath, svc.Namespace, svc.Name}, "/")
					services = append(services, s)
					s.Key = strings.Join(append([]string{zonePath, svc.Namespace, svc.Name}, strings.ToLower("_"+string(p.Protocol)), strings.ToLower("_"+string(p.Name))), "/")
					s.TargetStrip = 2
					services = append(services, s)
				}
			}
		}
	}
	return services
}

//ExternalSerial returns the serial of the external zone
func (k *Kubernetes) ExternalSerial(string) uint32 {
	return uint32(k.APIConn.Modified(true))
}
