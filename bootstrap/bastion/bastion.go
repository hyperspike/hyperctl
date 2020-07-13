package bastion

import (
	"net"
	"fmt"
	"log"
	"time"
	"errors"
	"regexp"
	"golang.org/x/crypto/ssh"
	"github.com/google/goexpect"
)

type Host struct {
	IP      *net.IP
	Ssh     *ssh.ClientConfig
	Client  *ssh.Client
	Session *ssh.Session
	Port    int
	User    string
}

func New(ip string, port int, key []byte, user string) *Host {
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}
	dur := 5 * time.Second
	addr4, _, err := net.ParseCIDR(ip)
	if err != nil {
		log.Fatal(err)
	}
	h := Host{
		User: user,
		Port: port,
		IP: &addr4,
		Ssh: &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
			},
			Timeout: dur,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		},
		Client:  nil,
		Session: nil,
	}
	return &h
}

func (h *Host) Connect() error {
	var tries int
	var err error
	for {
		h.Client, err = ssh.Dial("tcp", fmt.Sprintf("%v:%d", h.IP, h.Port), h.Ssh)
		if err == nil {
			return nil
		}
		time.Sleep(3 * time.Second)
		if tries > 10 {
			log.Printf("failed to establish connection %v, %v\n", h.IP, err)
			return errors.New("failed to establish new connection")
		}
		tries++
	}
	return nil
}

func (h *Host) Bastion(b *Host) error {
	if b.Client == nil {
		err := h.Connect()
		if err != nil {
			return err
		}
	}

	// Dial a connection to the service host, from the bastion
	conn, err := b.Client.Dial("tcp", fmt.Sprintf("%v:%d", h.IP, h.Port))
	if err != nil {
		log.Printf("failed to connect to host from bastion [%v]", err)
		return err
	}

	ncc, chans, reqs, err := ssh.NewClientConn(conn, fmt.Sprintf("%v:%d", h.IP, h.Port), h.Ssh)
	if err != nil {
		log.Printf("failed to connect to host from bastion [%v]", err)
		return err
	}

	h.Client = ssh.NewClient(ncc, chans, reqs)
	return nil
}

func (h *Host) Run(commands []string) error {
	timeout := 1 * time.Minute
	// promptRe := regexp.MustCompile(h.User)
	promptRe := regexp.MustCompile("~")

	if h.Client == nil {
		err := h.Connect()
		if err != nil {
			return err
		}
	}
	e, _, err := expect.SpawnSSH(h.Client, timeout)
	if err != nil {
		log.Printf("failed to spawn exec ssh %v\n", err)
		return err
	}
	defer e.Close()
	e.Expect(promptRe, timeout)

	var result string
	for _, cmd := range commands {
		e.Send(cmd + "\n")
		result, _, _ = e.Expect(promptRe, timeout)
		log.Printf("%v, %s: %s\n", h.IP, cmd, result)
	}
	e.Send("exit\n")
	return nil
}

func (h *Host) Close() {
	h.Client.Close()
	h.Client = nil
}

func (h *Host) Reconnect() {
	h.Close()
	h.Connect()
}
