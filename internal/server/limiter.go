package server

import (
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// connLimiter enforces, before authentication:
//   - a per-IP connection rate (token bucket),
//   - a per-IP cap on concurrent connections,
//   - a global cap on concurrent connections.
type connLimiter struct {
	mu       sync.Mutex
	perIP    map[string]*ipState
	active   int
	maxConns int
	maxPerIP int
	rate     rate.Limit
	burst    int
	maxIPs   int // bound on tracked IPs, so the map can't grow without limit
}

type ipState struct {
	lim    *rate.Limiter
	active int
}

func newConnLimiter(maxConns, maxPerIP int, r rate.Limit, burst, maxIPs int) *connLimiter {
	return &connLimiter{
		perIP:    map[string]*ipState{},
		maxConns: maxConns,
		maxPerIP: maxPerIP,
		rate:     r,
		burst:    burst,
		maxIPs:   maxIPs,
	}
}

// acquire reserves a slot for a connection from ip. On success the caller
// must call release exactly once when the connection ends.
func (l *connLimiter) acquire(ip string) (release func(), reason string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	st := l.perIP[ip]
	if st == nil {
		if len(l.perIP) >= l.maxIPs {
			l.sweep(now)
		}
		if len(l.perIP) >= l.maxIPs {
			return nil, "too many tracked clients"
		}
		st = &ipState{lim: rate.NewLimiter(l.rate, l.burst)}
		l.perIP[ip] = st
	}
	// Per-IP checks first, then the global cap, so a refused client never
	// holds a global slot.
	if !st.lim.AllowN(now, 1) {
		return nil, "rate limited"
	}
	if st.active >= l.maxPerIP {
		return nil, "too many connections from this address"
	}
	if l.active >= l.maxConns {
		return nil, "server busy"
	}
	st.active++
	l.active++

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			st.active--
			l.active--
			l.mu.Unlock()
		})
	}, ""
}

// sweep forgets idle IPs whose bucket has fully refilled; forgetting them
// loses no rate-limit state. Callers hold l.mu.
func (l *connLimiter) sweep(now time.Time) {
	for ip, st := range l.perIP {
		if st.active == 0 && st.lim.TokensAt(now) >= float64(l.burst) {
			delete(l.perIP, ip)
		}
	}
}

// limitedConn releases its limiter slot when closed.
type limitedConn struct {
	net.Conn
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

func remoteIP(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	return addr.String()
}
