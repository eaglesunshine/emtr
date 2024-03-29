// Package mtr TODO
package mtr

import (
	"container/ring"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/eaglesunshine/emtr/hop"
	"github.com/eaglesunshine/emtr/icmp"
)

// MTR TODO
type MTR struct {
	Count          int
	SrcAddress     string `json:"source"`
	mutex          *sync.RWMutex
	timeout        time.Duration
	interval       time.Duration
	Address        string `json:"destination"`
	hopsleep       time.Duration
	Statistic      map[int]*hop.HopStatistic `json:"statistic"`
	ringBufferSize int
	maxHops        int
	maxUnknownHops int
	ptrLookup      bool
}

// NewMTR TODO
func NewMTR(addr, srcAddr string, timeout time.Duration, interval time.Duration,
	hopsleep time.Duration, maxHops, maxUnknownHops, ringBufferSize int, ptr bool) (c *MTR, err error) {
	defer func() {
		if e := recover(); e != nil {
			log.Print(e)
			buf := make([]byte, 64<<10) // 64*2^10, 64KB
			buf = buf[:runtime.Stack(buf, false)]
			err = fmt.Errorf("panic recovered: %s\n %s", e, buf)
		}
	}()

	if net.ParseIP(addr) == nil {
		addrs, err := net.LookupHost(addr)
		if err != nil || len(addrs) == 0 {
			return nil, fmt.Errorf("invalid host or ip provided: %s", err)
		}
		addr = addrs[0]
	}
	if srcAddr == "" {
		if net.ParseIP(addr).To4() != nil {
			srcAddr = "0.0.0.0"
		} else {
			srcAddr = "::"
		}
	}
	return &MTR{
		Count:          3,
		SrcAddress:     srcAddr,
		interval:       interval,
		timeout:        timeout,
		hopsleep:       hopsleep,
		Address:        addr,
		mutex:          &sync.RWMutex{},
		Statistic:      map[int]*hop.HopStatistic{},
		maxHops:        maxHops,
		ringBufferSize: ringBufferSize,
		maxUnknownHops: maxUnknownHops,
		ptrLookup:      ptr,
	}, nil
}

func (m *MTR) registerStatistic(ttl int, r icmp.ICMPReturn) *hop.HopStatistic {
	s, ok := m.Statistic[ttl]
	if !ok {
		s = &hop.HopStatistic{
			Sent:           0,
			TTL:            ttl,
			Timeout:        m.timeout,
			Last:           r,
			Worst:          r,
			Lost:           0,
			Packets:        ring.New(m.ringBufferSize),
			RingBufferSize: m.ringBufferSize,
		}
		m.Statistic[ttl] = s
	}

	s.Last = r
	s.Sent++

	s.Targets = addTarget(s.Targets, r.Addr)

	s.Packets = s.Packets.Prev()
	s.Packets.Value = r

	if !r.Success {
		s.Lost++
		return s // do not count failed into statistics
	}

	s.SumElapsed = r.Elapsed + s.SumElapsed

	if !s.Best.Success || s.Best.Elapsed > r.Elapsed {
		s.Best = r
	}
	if s.Worst.Elapsed < r.Elapsed {
		s.Worst = r
	}

	return s
}

func addTarget(currentTargets []string, toAdd string) []string {
	for _, t := range currentTargets {
		if t == toAdd {
			// already added
			return currentTargets
		}
	}

	var newTargets []string
	if len(currentTargets) > 0 {
		// do not add no-ip target
		if toAdd == "" {
			return currentTargets
		}

		// remove no-ip target
		for _, t := range currentTargets {
			if t != "" {
				newTargets = append(newTargets, t)
			}
		}
	} else {
		newTargets = currentTargets
	}

	// add the new one
	return append(newTargets, toAdd)
}

// Run TODO
func (m *MTR) Run() (err error) {
	defer func() {
		if e := recover(); e != nil {
			log.Printf("discover failed: %v", e)
			buf := make([]byte, 64<<10)
			buf = buf[:runtime.Stack(buf, false)]
			err = fmt.Errorf("errgroup: panic recovered: %s\n %s", e, buf)
		}
	}()

	var handlers []func() error
	for i := 0; i < m.Count; i++ {
		handlers = append(handlers, func() error {
			return m.discover()
		})
	}

	return GoroutineNotPanic(handlers...)
}

// discover all hops on the route
func (m *MTR) discover() (err error) {
	rand.Seed(time.Now().UnixNano())
	seq := rand.Intn(math.MaxUint16)
	id := rand.Intn(math.MaxUint16) & 0xffff

	ipAddr := net.IPAddr{IP: net.ParseIP(m.Address)}

	for ttl := 1; ttl < m.maxHops; ttl++ {
		seq++
		time.Sleep(m.hopsleep)

		var hopReturn icmp.ICMPReturn

		if ipAddr.IP.To4() != nil {
			hopReturn, _ = icmp.SendDiscoverICMP(m.SrcAddress, &ipAddr, ttl, id, m.timeout, seq)
		} else {
			hopReturn, _ = icmp.SendDiscoverICMPv6(m.SrcAddress, &ipAddr, ttl, id, m.timeout, seq)
		}

		m.mutex.Lock()
		s := m.registerStatistic(ttl, hopReturn)
		s.Dest = &ipAddr
		s.PID = id
		m.mutex.Unlock()

		if hopReturn.Addr == m.Address {
			break
		}
	}

	return nil
}

// GoroutineNotPanic TODO
func GoroutineNotPanic(handlers ...func() error) (err error) {
	var wg sync.WaitGroup

	for _, f := range handlers {
		wg.Add(1)

		go func(handler func() error) {

			defer func() {
				if e := recover(); e != nil {
					log.Printf(err.Error())
					buf := make([]byte, 64<<10) // 64*2^10, 64KB
					buf = buf[:runtime.Stack(buf, false)]
					err = fmt.Errorf("panic recovered: %s\n %s", e, buf)
				}
				wg.Done()
			}()

			e := handler()
			if err == nil && e != nil {
				err = e
			}
		}(f)
	}

	wg.Wait()

	return
}
