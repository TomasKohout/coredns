package external

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/etcd/msg"
	"github.com/coredns/coredns/plugin/transfer"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Transfer implements transfer.Transferer
func (e *External) Transfer(zone string, serial uint32) (<-chan []dns.RR, error) {
	z := plugin.Zones(e.Zones).Matches(zone)
	if z != zone {
		return nil, transfer.ErrNotAuthoritative
	}

	ctx := context.Background()
	ch := make(chan []dns.RR, 2)
	if zone == "." {
		zone = ""
	}
	state := request.Request{Zone: zone}

	// SOA
	soa := e.soa(state)
	ch <- []dns.RR{soa}
	if serial != 0 && serial >= soa.Serial {
		close(ch)
		return ch, nil
	}

	go func() {
		// Add NS
		nsName := "ns1." + e.apex + "." + zone
		nsHdr := dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Ttl: e.ttl, Class: dns.ClassINET}
		ch <- []dns.RR{&dns.NS{Hdr: nsHdr, Ns: nsName}}

		// Add Nameserver A/AAAA records
		nsRecords := e.externalAddrFunc(state, e.headless)
		for i := range nsRecords {
			// externalAddrFunc returns incomplete header names, correct here
			nsRecords[i].Header().Name = nsName
			nsRecords[i].Header().Ttl = e.ttl
			ch <- []dns.RR{nsRecords[i]}
		}

		svcs := e.externalServicesFunc(zone, e.headless)
		srvSeen := make(map[string]struct{})
		// svcsGroup := make(map[string][]msg.Service)
		for i := range svcs {
			name := msg.Domain(svcs[i].Key)
			// if e.headless {
			// 	base, _ := dnsutil.TrimZone(name, state.Zone)

			// 	segs := dns.SplitDomainName(base)
	
			// 	// we have an endpoint from headless service here
			// 	// so add that base because we want to filter it out
			// 	if len(segs) == 3 {
			// 		baseSvcName := strings.Join(append(segs[1:], state.Zone), ".")
			// 		srvSeen[baseSvcName] = struct{}{}
			// 	}
			// }
			if svcs[i].TargetStrip == 0 {
				// if svcs[i].Group != "" {
				// 	svcsGroup[svcs[i].Group] = append(svcsGroup[svcs[i].Group], svcs[i])
				// }
				// Add Service A/AAAA records
				s := request.Request{Req: &dns.Msg{Question: []dns.Question{{Name: name}}}}
				as, _ := e.a(ctx, []msg.Service{svcs[i]}, s)
				if len(as) > 0 {
					ch <- as
				}
				aaaas, _ := e.aaaa(ctx, []msg.Service{svcs[i]}, s)
				if len(aaaas) > 0 {
					ch <- aaaas
				}
				// Add bare SRV record, ensuring uniqueness
				recs, _ := e.srv(ctx, []msg.Service{svcs[i]}, s)
				for _, srv := range recs {
					if !nameSeen(srvSeen, srv) {
						ch <- []dns.RR{srv}
					}
				}
				continue
			}
			// Add full SRV record, ensuring uniqueness
			s := request.Request{Req: &dns.Msg{Question: []dns.Question{{Name: name}}}}
			recs, _ := e.srv(ctx, []msg.Service{svcs[i]}, s)
			for _, srv := range recs {
				if !nameSeen(srvSeen, srv) {
					ch <- []dns.RR{srv}
				}
			}
		}
		// for i := range svcsGroup {
		// 	grouped := svcsGroup[i]
		// 	name := msg.Domain(grouped[0].Key)
		// 	// Add Service A/AAAA records
		// 	s := request.Request{Req: &dns.Msg{Question: []dns.Question{{Name: name}}}}
		// 	as, _ := e.a(ctx, grouped, s)
		// 	if len(as) > 0 {
		// 		ch <- as
		// 	}
		// 	aaaas, _ := e.aaaa(ctx, grouped, s)
		// 	if len(aaaas) > 0 {
		// 		ch <- aaaas
		// 	}
		// 	// Add bare SRV record, ensuring uniqueness
		// 	recs, _ := e.srv(ctx, grouped, s)
		// 	for _, srv := range recs {
		// 		if !nameSeen(srvSeen, srv) {
		// 			ch <- []dns.RR{srv}
		// 		}
		// 	}
		// }
		ch <- []dns.RR{soa}
		close(ch)
	}()

	return ch, nil
}

func nameSeen(namesSeen map[string]struct{}, rr dns.RR) bool {
	if _, duplicate := namesSeen[rr.Header().Name]; duplicate {
		return true
	}
	namesSeen[rr.Header().Name] = struct{}{}
	return false
}
