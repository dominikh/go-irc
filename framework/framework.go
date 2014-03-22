package framework

import (
	"fmt"
	"sync"

	"honnef.co/go/irc"
)

type WhoisHelper struct {
	mu      sync.RWMutex
	pending map[string][]whois
}

func (w *WhoisHelper) Register(mux interface {
	HandleFunc(command string, handler func(*irc.Client, *irc.Message))
}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// TODO better method name
	// TODO find a name for the anonymous interface
	if w.pending == nil {
		w.pending = make(map[string][]whois)
	}
	mux.HandleFunc("311", w.whoisUser)
	mux.HandleFunc("318", w.endOfWhois)
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
