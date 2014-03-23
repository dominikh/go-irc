package irc

import (
	"testing"
)

func msgEquals(one, other *Message) bool {

	if one.Raw != other.Raw ||
		one.Prefix != other.Prefix ||
		one.Command != other.Command {
		return false
	}
	if len(one.Params) != len(other.Params) {
		return false
	}
	for i := range one.Params {
		if one.Params[i] != other.Params[i] {
			return false
		}
	}
	return true
}

func ctcpEquals(one, other *CTCPMessage) bool {
	if one.Command != other.Command {
		return false
	}
	if len(one.Params) != len(other.Params) {
		return false
	}
	for i := range one.Params {
		if one.Params[i] != other.Params[i] {
			return false
		}
	}
	return true
}

func TestMessageParsing(t *testing.T) {
	table := []struct {
		in  string
		out *Message
	}{
		{"QUIT",
			&Message{Command: "QUIT"}},
		{"QUIT :some message",
			&Message{Command: "QUIT",
				Params: []string{"some message"}}},
		{"PRIVMSG #channel :some message",
			&Message{Command: "PRIVMSG",
				Params: []string{"#channel", "some message"}}},
		{"FOO bar baz :some message",
			&Message{Command: "FOO",
				Params: []string{"bar", "baz", "some message"}}},
		{"FOO :",
			&Message{Command: "FOO",
				Params: []string{""}}},
		{"FOO bar :",
			&Message{Command: "FOO",
				Params: []string{"bar", ""}}},
		{":example.com NOTICE * :*** Looking up your hostname...",
			&Message{Prefix: "example.com", Command: "NOTICE",
				Params: []string{"*", "*** Looking up your hostname..."}}},
		{":example.com 001 some_nick :Welcome to the Internet Relay Chat",
			&Message{Prefix: "example.com", Command: "001",
				Params: []string{"some_nick", "Welcome to the Internet Relay Chat"}}},
		{"FOO :bar ",
			&Message{Command: "FOO",
				Params: []string{"bar"}}},
	}

	for _, test := range table {
		test.out.Raw = test.in
		m := Parse(test.in)
		if !msgEquals(test.out, m) {
			t.Errorf("parsed %q, expected %#v, got %#v", test.in, test.out, m)
		}
	}
}

func TestCTCPParsing(t *testing.T) {
	table := []struct {
		in   string
		ctcp bool
		out  *CTCPMessage
	}{
		{"PRIVMSG #channel :some message",
			false,
			nil},
		{"PRIVMSG #channel :\u0001ACTION a test message\u0001",
			true,
			&CTCPMessage{Command: "ACTION", Params: []string{"a", "test", "message"}}},
	}

	for _, test := range table {
		m := Parse(test.in)
		isCTCP := m.IsCTCP()
		if isCTCP != test.ctcp {
			t.Fatalf("parsed %q, expected IsCTCP to return %s, got %s", test.in, test.ctcp, isCTCP)
		}
		if !isCTCP {
			continue
		}
		ctcp, err := m.CTCP()
		if err != nil {
			t.Fatalf("expected m.CTCP() not to return any error, got %q", err)
		}
		if !ctcpEquals(test.out, ctcp) {
			t.Errorf("parsed %q, expected %#v, got %#v", test.out, ctcp)
		}
	}
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMessageSplitting(t *testing.T) {
	table := []struct {
		in  string
		out []string
		n   int
	}{
		{
			"PRIVMSG #target :An ordinary message with a couple words",
			[]string{
				"PRIVMSG #target :An ordinary",
				"PRIVMSG #target :message with",
				"PRIVMSG #target :a couple",
				"PRIVMSG #target :words",
			},
			30,
		},

		{
			"PRIVMSG #target :A message with Pneumonoultramicroscopicsilicovolcanoconiosis",
			[]string{
				"PRIVMSG #target :A message",
				"PRIVMSG #target :with",
				"PRIVMSG #target :Pneumonoultra",
				"PRIVMSG #target :microscopicsi",
				"PRIVMSG #target :licovolcanoco",
				"PRIVMSG #target :niosis",
			},
			30,
		},
		{
			"PRIVMSG #target :驚いた彼は道を走っていった。",
			[]string{
				"PRIVMSG #target :驚いた彼",
				"PRIVMSG #target :は道を走",
				"PRIVMSG #target :っていっ",
				"PRIVMSG #target :た。",
			},
			30,
		},
		{
			"PRIVMSG #target :驚いた彼は道を走っていった。",
			[]string{
				"PRIVMSG #target :驚",
				"PRIVMSG #target :い",
				"PRIVMSG #target :た",
				"PRIVMSG #target :彼",
				"PRIVMSG #target :は",
				"PRIVMSG #target :道",
				"PRIVMSG #target :を",
				"PRIVMSG #target :走",
				"PRIVMSG #target :っ",
				"PRIVMSG #target :て",
				"PRIVMSG #target :い",
				"PRIVMSG #target :っ",
				"PRIVMSG #target :た",
				"PRIVMSG #target :。",
			},
			5,
		},
	}

	for i, test := range table {
		r := SplitMessage(test.in, test.n)
		if !stringsEqual(test.out, r) {
			t.Errorf("split #%d, expected %#v, got %#v", i, test.out, r)
		}
	}
}
