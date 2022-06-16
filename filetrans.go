package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/pkg/sftp"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func receiveCertificates(conn *ssh.Client, certs []cert) (err error) {
	logrus.Info("downloading certificates")
	client, err := sftp.NewClient(conn)
	if err != nil {
		return err
	}
	defer client.Close()
	for i, c := range certs {
		session, err := conn.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()
		c.ExportCryptoKey, err = rndpw(32)
		if err != nil {
			return err
		}
		err = session.Run(
			fmt.Sprintf(
				"/certificate export-certificate %s file-name=certmig_%s export-passphrase=%s",
				c.Name, c.Name, c.ExportCryptoKey,
			),
		)
		if err != nil {
			return fmt.Errorf("cannot run export: %w", err)
		}
		// download cert
		filename := fmt.Sprintf("certmig_%s.crt", c.Name)
		keyname := fmt.Sprintf("certmig_%s.key", c.Name)
		f, err := client.Open(filename)
		if err != nil {
			return err
		}
		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(f)
		if err != nil {
			return err
		}
		c.DataCrt = buf.Bytes()
		if err := client.Remove(filename); err != nil {
			return err
		}
		if c.FlagPrivateKey {
			// download key aswell
			f, err := client.Open(keyname)
			if err != nil {
				return err
			}
			buf := new(bytes.Buffer)
			_, err = buf.ReadFrom(f)
			if err != nil {
				return err
			}
			c.DataKey = buf.Bytes()
			if err := client.Remove(keyname); err != nil {
				return err
			}
		}
		certs[i] = c
	}
	return nil
}

func pushCertificates(conn *ssh.Client, certs []cert) error {
	logrus.Info("uploading certificates")
	client, err := sftp.NewClient(conn)
	if err != nil {
		return err
	}
	defer client.Close()
	for _, c := range certs {
		remove, err := uploadCert(client, c)
		if err != nil {
			return err
		}
		// wait for files to register in shell (i don't like this either...)
		time.Sleep(3 * time.Second)
		if err := importCert(conn, c); err != nil {
			return err
		}
		// wait for object to register in shell (i don't like this aswell...)
		time.Sleep(3 * time.Second)
		if err := updateTrusted(conn, c); err != nil {
			return fmt.Errorf("cannot set trusted state: %w", err)
		}
		if err := remove(); err != nil {
			return err
		}
	}
	return nil
}

func uploadCert(client *sftp.Client, crt cert) (func() error, error) {
	crtname := fmt.Sprintf("certmig_%s.crt", crt.Name)
	keyname := fmt.Sprintf("certmig_%s.key", crt.Name)
	// upload cert
	f, err := client.Create(crtname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := bytes.NewBuffer(crt.DataCrt)
	_, err = buf.WriteTo(f)
	if err != nil {
		return nil, err
	}
	if _, err := f.Stat(); err != nil {
		return nil, err
	}
	logrus.Debugf("certfile uploaded: %s", crtname)
	// upload privkey
	if crt.FlagPrivateKey {
		f, err := client.Create(keyname)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		buf := bytes.NewBuffer(crt.DataKey)
		_, err = buf.WriteTo(f)
		if err != nil {
			return nil, err
		}
		logrus.Debugf("keyfile uploaded: %s", keyname)
	}
	// prepare remove func
	remove := func() error {
		if err := client.Remove(crtname); err != nil {
			return err
		}
		logrus.Debugf("certfile removed: %s", crtname)
		if crt.FlagPrivateKey {
			if err := client.Remove(keyname); err != nil {
				return err
			}
			logrus.Debugf("keyfile removed: %s", keyname)
		}
		return nil
	}
	return remove, nil
}

func importCert(conn *ssh.Client, crt cert) error {
	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	cmd := fmt.Sprintf(
		"/certificate import name=%s file-name=certmig_%s.crt passphrase=%s",
		crt.Name, crt.Name, crt.ExportCryptoKey,
	)
	err = session.Run(cmd)
	if err != nil {
		return fmt.Errorf("failed command: %s", cmd)
	}
	logrus.Debugf("imported certfile: certmig_%s.crt", crt.Name)
	return nil
}

func updateTrusted(conn *ssh.Client, crt cert) error {
	sessionTrust, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer sessionTrust.Close()
	cmd := fmt.Sprintf("/certificate set %s trusted=%s", crt.Name, crt.Trusted)
	err = sessionTrust.Run(cmd)
	if err != nil {
		return fmt.Errorf("failed command: %s", cmd)
	}
	return nil
}

func rndpw(length int) (string, error) {
	const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		ret[i] = chars[n.Int64()]
	}
	return string(ret), nil
}
