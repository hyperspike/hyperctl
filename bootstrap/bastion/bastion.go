package bastion

import (
	"net"
	"fmt"
	log "github.com/sirupsen/logrus"
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
			// #nosec we're okay using this as I don't want to pollute host machine with keys
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
			goto done
		}
		time.Sleep(5 * time.Second)
		if tries > 20 {
			log.Printf("failed to establish connection %v, %v\n", h.IP, err)
			return errors.New("failed to establish new connection")
		}
		tries++
	}
	done: return nil
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
		log.Errorf("failed to spawn exec ssh %v\n", err)
		return err
	}
	defer e.Close()
	_, _, err = e.Expect(promptRe, timeout)
	if err != nil {
		log.Errorf("failed to get ssh prompt %v", err)
		return err
	}

	var result string
	for _, cmd := range commands {
		err = e.Send(cmd + "\n")
		if err != nil {
			log.Errorf("failed to send cmd %s, %v", cmd, err)
			return err
		}
		result, _, _ = e.Expect(promptRe, timeout)
		log.Printf("%v, %s: %s\n", h.IP, cmd, result)
	}
	err = e.Send("exit\n")
	if err != nil {
		log.Errorf("failed to hangup %v", err)
	}
	return nil
}

func (h *Host) Close() {
	err := h.Client.Close()
	if err != nil {
		log.Errorf("failed to close ssh connection %v", err)
	}
	h.Client = nil
}

func (h *Host) Reconnect() {
	h.Close()
	err := h.Connect()
	if err != nil {
		log.Errorf("failed to re-connect %v", err)
	}
}
