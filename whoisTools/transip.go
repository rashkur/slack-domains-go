package whoistools

import (
	// "fmt"
  
	"github.com/transip/gotransip"
	"github.com/transip/gotransip/domain"
	"time"
  )
  
  func TransipGetRenewalDate(accname string, apikey string, mydomain string) (time.Time, error) {
	// create new TransIP API SOAP client
	c, err := gotransip.NewSOAPClient(gotransip.ClientConfig{
	  AccountName: accname,
	  PrivateKeyPath: apikey})
	if err != nil {
	   return time.Now(), err
	}

	// type Domain struct {
	// 	Name              string         `xml:"name"`
	// 	Nameservers       []Nameserver   `xml:"nameservers>item"`
	// 	Contacts          []WhoisContact `xml:"contacts>item"`
	// 	DNSEntries        []DNSEntry     `xml:"dnsEntries>item"`
	// 	Branding          Branding       `xml:"branding"`
	// 	AuthorizationCode string         `xml:"authCode"`
	// 	IsLocked          bool           `xml:"isLocked"`
	// 	RegistrationDate  util.XMLTime   `xml:"registrationDate"`
	// 	RenewalDate       util.XMLTime   `xml:"renewalDate"`
	// }


	dominfo, err := domain.GetInfo(c, mydomain)
	if err != nil {
		return time.Now(), err
	}

	return dominfo.RenewalDate.Time, nil
  }

  func TransipGetWhois(accname string, apikey string, mydomain string) (string, error) {

	c, err := gotransip.NewSOAPClient(gotransip.ClientConfig{
		AccountName: accname,
		PrivateKeyPath: apikey})
	  if err != nil {
		return "", err
	  }

	domw, err := domain.GetWhois(c, mydomain)
	if err != nil {
		return "", err
	}

	return domw, nil
  }