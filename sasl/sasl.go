package sasl

import (
	"encoding/base64"
	"fmt"

	"honnef.co/go/irc"
)

type SASL struct {
	Mechanism Mechanism
}

type Mechanism interface {
	Name() string
	Generate(payload string) string
}

type Plain struct {
	User     string
	Password string
}

func (p *Plain) Name() string {
	return "PLAIN"
}

func (p *Plain) Generate(_ string) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s\x00%s\x00%s", p.User, p.User, p.Password)))
}

func (s *SASL) Authenticate(c *irc.Client) {
	c.Mux.HandleFunc("CAP", s.auth1)
	c.Mux.HandleFunc("AUTHENTICATE", s.auth2)
	c.Mux.HandleFunc("903", s.auth3)
	c.Mux.HandleFunc("904", s.auth3)
	c.Mux.HandleFunc("905", s.auth3)
	c.Mux.HandleFunc("907", s.auth3)
	c.Send("CAP REQ :sasl")
	c.Login()
}

func (s *SASL) auth1(c *irc.Client, m *irc.Message) {
	if m.Params[1] != "ACK" {
		s.auth3(c, m)
		return
	}
	if m.Params[2] != "sasl" {
		s.auth3(c, m)
		return
	}
	c.Send(fmt.Sprintf("AUTHENTICATE %s", s.Mechanism.Name()))
}

func (s *SASL) auth2(c *irc.Client, m *irc.Message) {
	// TODO check Params length
	payload := m.Params[0]
	c.Send(fmt.Sprintf("AUTHENTICATE %s", s.Mechanism.Generate(payload)))
}

func (s *SASL) auth3(c *irc.Client, m *irc.Message) {
	c.Send("CAP END")
}
