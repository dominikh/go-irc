package framework

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"time"
	"honnef.co/go/irc"
)

type WhoisHelper struct {
	*irc.Mux
	mu sync.RWMutex

	pending map[string][]whois
}

func NewWhoisHelper() *WhoisHelper {
	w := &WhoisHelper{
		Mux:     irc.NewMux(),
		pending: make(map[string][]whois),
	}

	w.HandleFunc("311", w.whoisUser)
	w.HandleFunc("318", w.endOfWhois)

	return w
}

func (w *WhoisHelper) whoisUser(c *irc.Client, m *irc.Message) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	// TODO check for right number of arguments
	whoises, ok := w.pending[m.Params[1]]
	if !ok {
		return
	}
	for _, whois := range whoises {
		whois.u.Nick = m.Params[1]
		whois.u.User = m.Params[2]
		whois.u.Host = m.Params[3]
		whois.u.Name = m.Params[5]
	}
}

func (w *WhoisHelper) endOfWhois(c *irc.Client, m *irc.Message) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// TODO check for right number of arguments
	whoises, ok := w.pending[m.Params[1]]
	if !ok {
		return
	}
	for _, whois := range whoises {
		whois.ch <- whois.u
	}
	delete(w.pending, m.Params[1])
}

func (w *WhoisHelper) Whois(c *irc.Client, nick string) *User {
	// TODO handle case if nick not found
	// TODO add timeout
	ch := make(chan *User)
	w.mu.Lock()
	s, ok := w.pending[nick]
	w.pending[nick] = append(s, whois{new(User), ch})
	if !ok {
		c.Send(fmt.Sprintf("WHOIS %s %s", nick, nick))
	}
	w.mu.Unlock()

	return <-ch
}

type whois struct {
	u  *User
	ch chan *User
}

type User struct {
	Nick     string
	Name     string
	User     string
	Host     string
	Channels []string
	Idle     int
}

type RegexpMuxer struct {
	mu   sync.RWMutex
	m    map[string][]pattern
	vars vars
}

type vars struct {
	sync.RWMutex
	m map[*irc.Message][]string
}

type pattern struct {
	rx *regexp.Regexp
	h  irc.Handler
}

func (mux *RegexpMuxer) Process(c *irc.Client, m *irc.Message) {
	mux.mu.RLock()
	defer mux.mu.RUnlock()
	candidates := mux.m[m.Signal]
	candidates = append(candidates, mux.m[""]...)
	for _, p := range candidates {
		p := p
		if p.rx == nil {
			go p.h.Process(c, m.Copy())
			continue
		}
		if len(m.Params) == 0 {
			continue
		}
		match := p.rx.FindStringSubmatch(m.Params[len(m.Params)-1])
		if match == nil {
			continue
		}
		m := m.Copy()
		mux.vars.Lock()
		mux.vars.m[m] = match
		mux.vars.Unlock()
		go func() {
			p.h.Process(c, m)
			mux.vars.Lock()
			delete(mux.vars.m, m)
			mux.vars.Unlock()
		}()
	}
}

func (mux *RegexpMuxer) Handle(pat string, handler irc.Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	parts := strings.SplitN(pat, "/", 2)
	signal := parts[0]
	var rx *regexp.Regexp
	if len(parts) == 2 {
		rx = regexp.MustCompile(parts[1])
	}
	mux.m[signal] = append(mux.m[signal], pattern{rx, handler})
}

func (mux *RegexpMuxer) HandleFunc(pattern string, handler func(*irc.Client, *irc.Message)) {
	mux.Handle(pattern, irc.HandlerFunc(handler))
}

func (mux *RegexpMuxer) Handlers(m *irc.Message) []irc.Handler {
	mux.mu.RLock()
	defer mux.mu.RUnlock()
	var hs []irc.Handler
	candidates := mux.m[m.Signal]
	candidates = append(candidates, mux.m[""]...)
	for _, p := range candidates {
		if p.rx == nil {
			hs = append(hs, p.h)
			continue
		}
		if len(m.Params) == 0 {
			continue
		}
		if p.rx.MatchString(m.Params[len(m.Params)-1]) {
			hs = append(hs, p.h)
		}
	}

	return hs
}

func (mux *RegexpMuxer) Vars(m *irc.Message) []string {
	mux.vars.RLock()
	defer mux.vars.RUnlock()
	return mux.vars.m[m]
}

func NewRegexpMuxer() *RegexpMuxer {
	return &RegexpMuxer{
		m:    make(map[string][]pattern),
		vars: vars{m: make(map[*irc.Message][]string)},
	}
}

func AvoidNickCollision(client *irc.Client, fn func(oldNick string) (newNick string)) {
	client.Mux.HandleFunc(irc.ERR_NICKNAMEINUSE, func(c *irc.Client, m *irc.Message) {
		if c.Connected() {
			return
		}
		c.SetNick(fn(m.Params[1]))
	})
}

func SimpleNickChanger(suffix string) func(oldNick string) (newNick string) {
	return func(old string) string {
		return old + suffix
	}
}

type NickRegainer struct {
	*irc.Mux
	mu       sync.Mutex
	wanted   string
	client   *irc.Client
	on       bool
	interval time.Duration
	quit     chan struct{}
	hasQuit  chan struct{}
}

func NewNickRegainer(client *irc.Client, wanted string, interval time.Duration) *NickRegainer {
	mux := irc.NewMux()

	nr := &NickRegainer{
		Mux:      mux,
		wanted:   wanted,
		client:   client,
		interval: interval,
	}

	return nr
}

func (nr *NickRegainer) Start() {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	if nr.on {
		return
	}
	nr.quit = make(chan struct{})
	nr.hasQuit = make(chan struct{})
	nr.on = true
	go nr.monitor()
}

func (nr *NickRegainer) Stop() {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	if !nr.on {
		return
	}
	close(nr.quit)
	<-nr.hasQuit
	nr.on = false
}

func (nr *NickRegainer) SetWanted(wanted string) {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	nr.wanted = wanted
}

func (nr *NickRegainer) SetInterval(d time.Duration) {
	nr.mu.Lock()
	wasOn := nr.on
	if nr.on {
		nr.Stop()
	}
	nr.interval = d
	if wasOn {
		nr.Start()
	}
}

func (nr *NickRegainer) monitor() {
	ticker := time.NewTicker(nr.interval)
	for {
		select {
		case <-ticker.C:
			if !nr.client.Connected() {
				continue
			}
			if nr.client.CurrentNick() == nr.wanted {
				continue
			}
			nr.client.SetNick(nr.wanted)
		case <-nr.quit:
			ticker.Stop()
			close(nr.hasQuit)
			return
		}
	}
}

func CTCPTime(c *irc.Client, m *irc.Message) {
	c.ReplyCTCP(m, time.Now().Format("Mon Jan 02 15:04:05 MST 2006"))
}

func CTCPPing(c *irc.Client, m *irc.Message) {
	ctcp, _ := m.CTCP()
	c.ReplyCTCP(m, strings.Join(ctcp.Params, " "))
}
