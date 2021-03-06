package framework // import "honnef.co/go/irc/framework"

import (
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"time"
	"honnef.co/go/irc"
)

type User struct {
	Nick       string
	Name       string
	User       string
	Host       string
	Channels   []string
	Idle       int
	Oper       bool
	SignedOnAt time.Time
	Account    string
}

func Whois(c *irc.Client, co *Coalesce, nick string) User {
	// TODO handle 263 (rate limit), 401 (NOSUCHNICK), 402 (NOSUCHSERVER)
	ch := make(chan []*irc.Message, 1)
	new := co.Subscribe(
		[]string{
			irc.RPL_WHOISUSER,
			irc.RPL_WHOISOPERATOR,
			irc.RPL_WHOISIDLE,
			irc.RPL_ENDOFWHOIS,
			irc.RPL_WHOISCHANNELS,
			irc.RPL_WHOISACCOUNT,
			irc.ERR_NOSUCHNICK,
			irc.ERR_NOSUCHSERVER,
		},
		[]string{
			irc.RPL_ENDOFWHOIS,
			irc.ERR_NOSUCHNICK,
			irc.ERR_NOSUCHSERVER,
		}, nick, ch)
	if new {
		c.Send(fmt.Sprintf("WHOIS %s %s", nick, nick))
	}
	u := User{}
	msgs := <-ch
	for _, msg := range msgs {
		switch msg.Command {
		case irc.RPL_WHOISUSER:
			u.Nick = msg.Params[1]
			u.User = msg.Params[2]
			u.Host = msg.Params[3]
			u.Name = msg.Params[5]
		case irc.RPL_WHOISOPERATOR:
			u.Oper = true
		case irc.RPL_WHOISIDLE:
			i, _ := strconv.Atoi(msg.Params[2])
			u.Idle = i
			i, _ = strconv.Atoi(msg.Params[3])
			u.SignedOnAt = time.Unix(int64(i), 0)
		case irc.RPL_WHOISCHANNELS:
			u.Channels = strings.Fields(msg.Params[2])
		case irc.RPL_WHOISACCOUNT:
			u.Account = msg.Params[2]
		}
	}
	return u
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

func AvoidNickCollision(fn func(oldNick string) (newNick string)) irc.HandlerFunc {
	return func(c *irc.Client, m *irc.Message) {
		if c.Connected() {
			return
		}
		c.SetNick(fn(m.Params[1]))
	}
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

func StaticCTCPReply(reply string) irc.HandlerFunc {
	return func(c *irc.Client, m *irc.Message) {
		c.ReplyCTCP(m, reply)
	}
}

type Input struct {
	Command string
	Param   string
}

type Interested struct {
	Messages []*irc.Message
	EndedBy  []string
	Inform   []chan []*irc.Message
}

type Coalesce struct {
	mu sync.Mutex
	m  map[Input]*Interested
}

func NewCoalesce() *Coalesce {
	return &Coalesce{m: make(map[Input]*Interested)}
}

func (co *Coalesce) Subscribe(commands []string, ends []string,
	param string, ch chan []*irc.Message) (new bool) {

	// FIXME handle timeouts of sent requests
	co.mu.Lock()
	defer co.mu.Unlock()
	var interested *Interested
	both := []string{}
	both = append(both, commands...)
	both = append(both, ends...)
	for _, c := range commands {
		input := Input{c, param}
		var ok bool
		interested, ok = co.m[input]
		if ok {
			break
		}
	}

	if interested == nil {
		new = true
		interested = &Interested{}
	}

	for _, c := range commands {
		input := Input{c, param}
		co.m[input] = interested
	}

	interested.EndedBy = ends
	interested.Inform = append(interested.Inform, ch)
	return new
}

func (co *Coalesce) Process(c *irc.Client, m *irc.Message) {
	co.mu.Lock()
	defer co.mu.Unlock()

	if len(m.Params) < 2 {
		return
	}
	input := Input{Command: m.Command, Param: m.Params[1]}
	interested, ok := co.m[input]
	if !ok {
		return
	}
	interested.Messages = append(interested.Messages, m)
	inform := false
	for _, s := range interested.EndedBy {
		if s == m.Command {
			inform = true
			break
		}
	}
	if !inform {
		return
	}
	for _, ch := range interested.Inform {
		messages := make([]*irc.Message, len(interested.Messages))
		copy(messages, interested.Messages)
		ch <- messages
	}

	for key, value := range co.m {
		if value == interested {
			delete(co.m, key)
		}
	}
}

// Retry executes a function in a loop that continues as long as the
// function's error return is a temporary network error, a timeout or
// an EOF. On all other errors, or no error at all, it will terminate.
//
// This function can be used for a simple reconnect loop that only
// reconnects on network failure and doesn't reconnect in the case of
// a programming error or an intended termination of the connection.
func Retry(fn func() error) error {
	var err error
	for {
		if err != nil {
			log.Printf("Reconnecting due to error: %s", err)
		}
		err = fn()
		if err == nil {
			return nil
		}

		if err, ok := err.(*net.OpError); ok && (err.Temporary() || err.Timeout()) {
			// TODO exponential backoff
			time.Sleep(1 * time.Second)
			continue
		}
		if err == io.EOF {
			time.Sleep(1 * time.Second)
			continue
		}
		return err
	}
}
