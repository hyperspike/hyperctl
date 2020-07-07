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
}

func New(ip string, port int, key []byte, user string) Host {
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
		IP: &addr4,
		Ssh: &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
			},
			Timeout: dur,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		},
	}
	return h
}

func (h Host) Connect() error {
	var tries int
	var err error
	for {
		h.Client, err = ssh.Dial("tcp", fmt.Sprintf("%v:%d", h.IP, h.Port), h.Ssh)
		if err != nil {
			log.Printf("failed to connect %v, %v\n", h.IP, err)
		} else {
			return nil
		}
		time.Sleep(3 * time.Second)
		if tries > 10 {
			log.Printf("failed to establish connection %v, %v\n", h.IP, err)
			return errors.New("failed to establish new connection")
		}
	}
	h.Session, err = h.Client.NewSession()
	if err != nil {
		h.Session = nil
		return err
	}
	return nil
}

func (h Host) Run(commands []string) error {
	timeout := 1 * time.Minute
	promptRe := regexp.MustCompile("#")

	e, _, err := expect.SpawnSSH(h.Client, timeout)
	if err != nil {
		log.Printf("failed to spawn exec ssh %v\n", err)
		return err
	}
	e.Expect(promptRe, timeout)

	var result string
	for _, cmd := range commands {
		e.Send(cmd)
		_, _, _ = e.Expect(promptRe, timeout)
		result, _, _ = e.Expect(promptRe, timeout)
		log.Printf("%v, %s: %s\n", h.IP, cmd, result)
	}
	e.Send("exit")
	return nil
}
