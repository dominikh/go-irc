package sasl // import "honnef.co/go/irc/sasl"

import (
	"encoding/base64"
	"fmt"

	"honnef.co/go/irc"
)

type SASL struct {
	*irc.Mux
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

func New(m Mechanism) *SASL {
	s := &SASL{irc.NewMux(), m}

	s.HandleFunc("CAP", s.auth1)
	s.HandleFunc("AUTHENTICATE", s.auth2)
	s.HandleFunc(irc.RPL_SASLSUCCESS, s.auth3)
	s.HandleFunc(irc.RPL_SASLFAILED, s.auth3)
	s.HandleFunc(irc.RPL_SASLERROR, s.auth3)
	s.HandleFunc(irc.RPL_SASLALREADYAUTH, s.auth3)

	return s
}

func (p *Plain) Name() string {
	return "PLAIN"
}

func (p *Plain) Generate(_ string) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s\x00%s\x00%s", p.User, p.User, p.Password)))
}

func (s *SASL) Authenticate(c *irc.Client) {
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
