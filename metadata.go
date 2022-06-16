package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type cert struct {
	ID               int
	FlagPrivateKey   bool
	FlagCRL          bool
	FlagSmartCardKey bool
	FlagAuthority    bool
	FlagIssued       bool
	FlagRevoked      bool
	FlagExpired      bool
	FlagTrusted      bool
	Name             string
	Issuer           string
	DigestAlgorithm  string
	KeyType          string
	CommonName       string
	KeySize          string
	SubjectAltName   string
	DaysValid        string
	Trusted          string
	KeyUsage         string
	CA               string
	SerialNumber     string
	Fingerprint      string
	Akid             string
	Skid             string
	InvalidBefore    string
	InvalidAfter     string
	ExpiresAfter     string
	ExportCryptoKey  string
	DataCrt          []byte
	DataKey          []byte
}

func getCertList(conn *ssh.Client) ([]cert, error) {
	logrus.Info("fetching metadata")
	session, err := conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	buff := new(bytes.Buffer)
	session.Stdout = buff
	if err := session.Run("/certificate print terse"); err != nil {
		return nil, err
	}
	certs, err := parseCertificates(buff.String())
	if err != nil {
		return nil, err
	}
	return certs, nil
}

func parseCertificates(out string) ([]cert, error) {
	outs := strings.Split(out, "\r\n")
	certs := make([]cert, 0)
	for _, o := range outs {
		crt := new(cert)
		entry := strings.SplitN(o, "name=", 2)
		if len(entry) != 2 {
			continue
		}
		entry[1] = fmt.Sprintf("name=%s", entry[1])
		if err := parseCertificateFlags(crt, entry[0]); err != nil {
			return nil, err
		}
		if err := parseCertificateFields(crt, strings.Split(entry[1], " ")); err != nil {
			return nil, err
		}
		certs = append(certs, *crt)
	}
	return certs, nil
}

func parseCertificateFlags(c *cert, flags string) (err error) {
	// get id
	re := regexp.MustCompile("[0-9]+")
	c.ID, err = strconv.Atoi(string(re.Find([]byte(flags))))
	if err != nil {
		return
	}
	// get flags
	c.FlagPrivateKey = strings.ContainsRune(flags, 'K')
	c.FlagCRL = strings.ContainsRune(flags, 'L')
	c.FlagSmartCardKey = strings.ContainsRune(flags, 'C')
	c.FlagAuthority = strings.ContainsRune(flags, 'A')
	c.FlagIssued = strings.ContainsRune(flags, 'I')
	c.FlagRevoked = strings.ContainsRune(flags, 'R')
	c.FlagExpired = strings.ContainsRune(flags, 'E')
	c.FlagTrusted = strings.ContainsRune(flags, 'T')
	return nil
}

func parseCertificateFields(c *cert, fields []string) error {
	for fi := 0; fi < len(fields); fi++ {
		field := fields[fi]
		if len(strings.TrimSpace(field)) == 0 {
			continue
		}
		if strings.HasPrefix(field, "invalid-before=") ||
			strings.HasPrefix(field, "invalid-after=") {
			field = fmt.Sprintf("%s %s", field, fields[fi+1])
			fi++
		}
		vals := strings.SplitN(field, "=", 2)
		if len(vals) != 2 {
			return fmt.Errorf("could not parse field value: %s", field)
		}
		switch vals[0] {
		case "name":
			c.Name = vals[1]
		case "issuer":
			c.Issuer = vals[1]
		case "digest-algorithm":
			c.DigestAlgorithm = vals[1]
		case "key-type":
			c.KeyType = vals[1]
		case "common-name":
			c.CommonName = vals[1]
		case "key-size":
			c.KeySize = vals[1]
		case "subject-alt-name":
			c.SubjectAltName = vals[1]
		case "days-valid":
			c.DaysValid = vals[1]
		case "trusted":
			c.Trusted = vals[1]
		case "key-usage":
			c.KeyUsage = vals[1]
		case "ca":
			c.CA = vals[1]
		case "serial-number":
			c.SerialNumber = vals[1]
		case "fingerprint":
			c.Fingerprint = vals[1]
		case "akid":
			c.Akid = vals[1]
		case "skid":
			c.Skid = vals[1]
		case "invalid-before":
			c.InvalidBefore = vals[1]
		case "invalid-after":
			c.InvalidAfter = vals[1]
		case "expires-after":
			c.ExpiresAfter = vals[1]
		default:
			logrus.WithField("field", vals[0]).Warn("unknown metadata field")
		}
	}
	return nil
}
