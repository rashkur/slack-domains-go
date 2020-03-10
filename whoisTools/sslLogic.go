package whoistools

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"time"
)

// var uTC = false
// var userTempl string
var skipVerify = false
var timeoutSeconds = 3

const defaultPort = "443"

type sslCert struct {
	DomainName string    `json:"domainName"`
	IP         string    `json:"ip"`
	Issuer     string    `json:"issuer"`
	CommonName string    `json:"commonName"`
	SANs       []string  `json:"sans"`
	NotBefore  time.Time `json:"notBefore"`
	NotAfter   time.Time `json:"notAfter"`
	Error      error     `json:"error"`
	certChain  []*x509.Certificate
}

// CheckSsl using for validate site's ssl certificate
func CheckSsl(ds DomainStruct,
	rs ReplyStruct,
	ReplyChan chan<- ReplyStruct,
	expires10DaysChan chan<- ReplyStruct,
	expires30DaysChan chan<- ReplyStruct,
	expires60DaysChan chan<- ReplyStruct,
	expiredChan chan<- ReplyStruct,
	ErrorChan chan<- ReplyStruct,
	threadCounter interface{}) {

	var defineTcReply = func() {
		switch tc := threadCounter.(type) {
		case chan bool:
			tc <- true
		default:
		}
	}

	ns := checkCert(rs.Domain, ds.SSLDomain)

	var ret ReplyStruct
	ret.ID = rs.ID
	ret.Account = rs.Account
	ret.Domain = rs.Domain
	ret.SlackUser = rs.SlackUser
	ret.SlackChannel = rs.SlackChannel
	ret.MessageType = 4

	tempbuf := []string{ret.Domain, "ssl"}
	ret.Domain = strings.Join(tempbuf, " ")

	if ns.Error != nil {
		ret.Error = ns.Error
		// log.Printf("Unable to get %q: %s\n", url, err)
		// return

		ErrorChan <- ret
		defineTcReply()
		return
	}

	parsedTime, isExpiring, expirationTerm, isExpired, err := getDateDiff(ns.NotAfter)
	if err != nil {
		ret.Error = err

		ErrorChan <- ret
		defineTcReply()
		return
	}

	ret.SslIssuer = ns.Issuer
	ret.ExpiredDate = ns.NotAfter
	ret.IsExpiring = isExpiring
	ret.IsExpired = isExpired
	ret.ExpirationTerm = expirationTerm
	ret.Date = parsedTime.String()

	if isExpiring {
		ret.Error = err

		// every expire is going to it's own channel
		// for ssl we only need 2 expiration levels
		switch expirationTerm {
		case Next10DaysExpiration:
			expires10DaysChan <- ret
		case Next30DaysExpiration:
			expires30DaysChan <- ret
			// case Next60DaysExpiration:
			// 	expires60DaysChan <- ret
		}

		defineTcReply()
		return
	}

	if isExpired {
		ret.Error = err

		expiredChan <- ret
		defineTcReply()
		return
	}

	ReplyChan <- ret
	defineTcReply()
	return
}

func splitHostPort(hostport string) (string, string, error) {
	if !strings.Contains(hostport, ":") {
		return hostport, defaultPort, nil
	}

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", "", err
	}

	if port == "" {
		port = defaultPort
	}

	return host, port, nil
}

func serverCert(host, port string, SSLDomain string) ([]*x509.Certificate, string, error) {
	d := &net.Dialer{
		Timeout: time.Duration(timeoutSeconds) * time.Second,
	}
	
	tlsconfig := tls.Config{InsecureSkipVerify: skipVerify}
	if len(SSLDomain) > 1 { 
        tlsconfig = tls.Config{InsecureSkipVerify: skipVerify, ServerName: SSLDomain}
	}

	conn, err := tls.DialWithDialer(d, "tcp", host+":"+port, &tlsconfig)
	if err != nil {
		return []*x509.Certificate{&x509.Certificate{}}, "", err
	}
	defer conn.Close()

	addr := conn.RemoteAddr()
	ip, _, _ := net.SplitHostPort(addr.String())
	cert := conn.ConnectionState().PeerCertificates

	return cert, ip, nil
}

func checkCert(hostport string, SSLDomain string) *sslCert {

	host, port, err := splitHostPort(hostport)
	if err != nil {
		return &sslCert{DomainName: host, Error: err}
	}

	certChain, ip, err := serverCert(host, port, SSLDomain)
	if err != nil {
		// fmt.Printf("serverCert error:%s\n", err)
		return &sslCert{DomainName: host, Error: err}
	}
	cert := certChain[0]

	// fmt.Printf("DomainName:%s\nIP:%s\nCommonName:%s\n", host, ip, cert.Subject.CommonName)

	return &sslCert{
		DomainName: host,
		IP:         ip,
		Issuer:     cert.Issuer.CommonName,
		CommonName: cert.Subject.CommonName,
		SANs:       cert.DNSNames,
		// NotBefore:  cert.NotBefore.In(loc).String(),
		// NotAfter:   cert.NotAfter.In(loc).String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Error:     nil,
		certChain: certChain,
	}
}
