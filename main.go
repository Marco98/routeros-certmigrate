package main

import (
	"encoding/gob"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	SSH_TIMEOUT = 3 * time.Second
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "ros-crtmigrate SOURCEADDR DSTADDR",
		Short: "A tool to quickly export and import certificates in Mikrotik's RouterOS from and to a file or router",
		Args:  cobra.ExactArgs(2),
		RunE:  run,
	}
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "print more info when running")
	rootCmd.PersistentFlags().BoolP("read", "r", false, "read from file instead of a remote router")
	rootCmd.PersistentFlags().BoolP("write", "w", false, "write to file instead of a remote router")
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatalf("error: %s\n", err.Error())
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	if f, err := cmd.PersistentFlags().GetBool("verbose"); err == nil && f {
		logrus.SetLevel(logrus.DebugLevel)
	}
	var certs []cert
	var err error
	var f bool
	if f, err = cmd.PersistentFlags().GetBool("read"); err == nil && f {
		certs, err = pullCertsFile(args[0])
	} else {
		certs, err = pullCertsRemote(args[0])
	}
	if err != nil {
		return err
	}
	if f, err = cmd.PersistentFlags().GetBool("write"); err == nil && f {
		err = pushCertsFile(args[1], certs)
	} else {
		err = pushCertsRemote(args[1], certs)
	}
	if err != nil {
		return err
	}
	logrus.WithField("count", len(certs)).Info("certificates migrated")
	return nil
}

func pullCertsRemote(addr string) ([]cert, error) {
	conn, err := createConn(addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs, err := getCertList(conn)
	if err != nil {
		return nil, err
	}
	if err := receiveCertificates(conn, certs); err != nil {
		return nil, err
	}
	return certs, nil
}

func pushCertsRemote(addr string, c []cert) error {
	conn, err := createConn(addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return pushCertificates(conn, c)
}

func pullCertsFile(path string) ([]cert, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var certs []cert
	if err := gob.NewDecoder(f).Decode(&certs); err != nil {
		return nil, err
	}
	return certs, nil
}

func pushCertsFile(path string, c []cert) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := gob.NewEncoder(f).Encode(c); err != nil {
		return err
	}
	return nil
}

func createConn(addr string) (*ssh.Client, error) {
	usr, addr := parseAdress(addr)
	pass, err := getPassword(usr, addr)
	if err != nil {
		return nil, fmt.Errorf("cannot read password: %w", err)
	}
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            usr,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         SSH_TIMEOUT,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("connect failed: %w", err)
	}
	return conn, nil
}

func parseAdress(in string) (user, address string) {
	str1 := strings.SplitN(in, "@", 2)
	user = "admin"
	address = str1[0]
	if len(str1) == 2 {
		user = str1[0]
		address = str1[1]
	}
	if !strings.ContainsRune(address, ':') {
		address = fmt.Sprintf("%s:22", address)
	}
	return user, address
}

func getPassword(usr, addr string) (string, error) {
	fmt.Printf("%s@%s's password: ", usr, addr)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return strings.TrimSpace(string(bytePassword)), nil
}
