package whoistools

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"strings"
	"time"
)

const (
	iana             = "whois.iana.org"
	whoisPort        = "43"
	dialRetriesCount = 10
	domainChkRndMin  = 1
	domainChkRndMax  = 60
)

func random(min, max int, durtype time.Duration) time.Duration {
	rand.Seed(time.Now().Unix())
	return time.Duration(rand.Intn(max-min)+min) * durtype
}

func getWhoisServer(str string, substr string, substrLen int) (server string, err error) {
	start := strings.Index(str, substr)
	if start == -1 {
		return
	}

	start += substrLen
	end := strings.Index(str[start:], "\n")
	return strings.Trim(strings.Replace(str[start:start+end], "\r", "", -1), " "), nil
}

func Whois(domain string) (result string, err error) {
	domain = strings.Trim(strings.Trim(domain, " "), ".")
	if domain == "" {
		err = fmt.Errorf("Domain is empty")
		return
	}

	// at first we will get basic info about domain from iana
	result, err = query(domain, "")
	if err != nil {
		return
	}

	// at second we will get actual whois server from iana
	server, err := getWhoisServer(result, "whois:", 6)
	if err != nil {
		return
	}

	if server == "" {
		return
	}

	// at third we will get whois data from actial server and add it to step one
	tmpResult, err := query(domain, server)
	if err != nil {
		return
	}

	result += tmpResult

	return
}

func query(domain string, whoisServer string) (result string, err error) {
	var server string
	if whoisServer == "" {
		server = iana
	} else {
		server = whoisServer
	}

	for i := 0; i <= dialRetriesCount; i++ {
		conn, e := net.DialTimeout("tcp", net.JoinHostPort(server, whoisPort), time.Second*10)
		if e != nil {
			//err = e
			if i == dialRetriesCount {
				//Error.Println("After", i, "retries failed to create connection for", domain, "with error:", e)
				return
			}
			time.Sleep(random(domainChkRndMin, domainChkRndMax, time.Second))
			continue
			//return
		}

		defer conn.Close()
		conn.Write([]byte(domain + "\r\n"))
		buffer, e := ioutil.ReadAll(conn)
		if e != nil {
			//err = e
			if i == dialRetriesCount {
				//Error.Println("Failed to read from connection:", e)
				return
			}
			time.Sleep(random(domainChkRndMin, domainChkRndMax, time.Second))
			continue
			//return
		}

		result = string(buffer)

		if e == nil {
			return result, e
		}
	}

	return
}
