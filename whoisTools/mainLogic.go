package whoistools

import (
	"../whois-parser-go"
	"github.com/slack-go/slack"
	"strings"
	"time"
	"errors"
	"strconv"
)

func (env *Env) FEL(slackChannel string, 
	rtm slack.RTM, 
	transip_accname string, 
	transip_apikey string) {
	printReportsSignal := make(chan bool)

	// Can be optimised - if we dont need to work with domains having "Ok" status - just implement counter in place of okStorage
	okStorage,
	expires10Storage,
	expires30Storage,
	expires60Storage,
	expiredStorage,
	errorStorage := WhoisReplys{},
	WhoisReplys{},
	WhoisReplys{},
	WhoisReplys{},
	WhoisReplys{},
	WhoisReplys{}

	// full expiration reports printer
	(*Env).FullExpirationList(env,
		&okStorage,
		&expires10Storage,
		&expires30Storage,
		&expires60Storage,
		&expiredStorage,
		&errorStorage,
		printReportsSignal,
		transip_accname, 
		transip_apikey)

	PrintReport(rtm,
		printReportsSignal,
		slackChannel,
		&okStorage,
		&expires10Storage,
		&expires30Storage,
		&expires60Storage,
		&expiredStorage,
		&errorStorage)
}

// GetExpirationDateAsync - self-explanatory name
func GetExpirationDateAsync(
	ds DomainStruct,
	rs ReplyStruct,
	okChan chan<- ReplyStruct,
	expires10DaysChan chan<- ReplyStruct,
	expires30DaysChan chan<- ReplyStruct,
	expires60DaysChan chan<- ReplyStruct,
	expiredChan chan<- ReplyStruct,
	errorChan chan<- ReplyStruct,
	threadCounter chan<- bool,
	transip_accname string, 
	transip_apikey string) {

	var ret ReplyStruct
	ret.ID = rs.ID
	ret.Domain = rs.Domain
	ret.Account = rs.Account
	ret.SlackUser = rs.SlackUser
	ret.SlackChannel = rs.SlackChannel
	ret.Server = rs.Server

	// all domains with invalid whois going to error channel

	var transipDomainRenewalDate = time.Now()
	var result = ""
	var err = errors.New("")

	if ds.Provider == 0 {
		result, err = Whois(rs.Domain)
		if err != nil {
			ret.Error = err

			errorChan <- ret
			threadCounter <- true
			return
		}
	}

	if ds.Provider == 1 {
		transipDomainRenewalDate, err = TransipGetRenewalDate(transip_accname, transip_apikey, rs.Domain)
		if err != nil {
			ret.Error = err
	
			errorChan <- ret
			threadCounter <- true
			return
		}
		
		result, err = TransipGetWhois(transip_accname, transip_apikey, rs.Domain)
		if err != nil {
			ret.Error = err
	
			errorChan <- ret
			threadCounter <- true
			return
		}
	}

	whoisParserRet, err := whois_parser.Parse(result)
	if err != nil {
		ret.Error = err

		errorChan <- ret
		threadCounter <- true
		return
	}

	// domains with valid whois going to date diff function for sorting to
	// okChan - domains without expiration problems
	// expiresChan - domains which will be expired soon
	// expiredChan - domains which already expired

	gddval := transipDomainRenewalDate.String() //time.now or actual renewal date
	if ds.Provider != 1 {
		gddval = whoisParserRet.Registrar.ExpirationDate
	}
	
	gdd, isExpiring, expirationTerm, isExpired, err := getDateDiff(gddval)
	if err != nil {
		ret.Error = err

		errorChan <- ret
		threadCounter <- true
		return
	}

	ret.Error = err
	ret.Date = whoisParserRet.Registrar.ExpirationDate
	ret.IsExpiring = isExpiring
	ret.ExpirationTerm = expirationTerm
	ret.IsExpired = isExpired
	ret.ExpiredDate = gdd

	if isExpiring {
		// every expire is going to it's own channel
		switch expirationTerm {
		case Next10DaysExpiration:
			expires10DaysChan <- ret
		case Next30DaysExpiration:
			expires30DaysChan <- ret
		case Next60DaysExpiration:
			expires60DaysChan <- ret
		}

		threadCounter <- true
		return
	}

	if isExpired {
		expiredChan <- ret
		threadCounter <- true
		return
	}

	okChan <- ret
	threadCounter <- true
	return
}

// FullExpirationList ...
func (env *Env) FullExpirationList(
	okStorage *WhoisReplys,
	expires10Storage *WhoisReplys,
	expires30Storage *WhoisReplys,
	expires60Storage *WhoisReplys,
	expiredStorage *WhoisReplys,
	errorStorage *WhoisReplys,
	printReport chan<- bool,
	transip_accname string, 
	transip_apikey string) {

	//get total amount of domains
	rows, err := env.DB.Query("SELECT COUNT(*) FROM sites WHERE checkwhois=1 OR checkssl=1")
	CheckErr(err)
	var numOfDomains int
	for rows.Next() {
		err = rows.Scan(&numOfDomains)
		CheckErr(err)
	}
        rows.Close()
	// get all records in loop and run check
	rows, err = env.DB.Query("SELECT * FROM sites WHERE checkwhois=1 OR checkssl=1 ORDER BY RANDOM()")
	CheckErr(err)


	// var server string
       

	okChan := make(chan ReplyStruct, 100)
	expires10DaysChan := make(chan ReplyStruct, 100)
	expires30DaysChan := make(chan ReplyStruct, 100)
	expires60DaysChan := make(chan ReplyStruct, 100)
	expiredChan := make(chan ReplyStruct, 100)
	errorChan := make(chan ReplyStruct, 100)

	threadCounter := make(chan bool, 100)
	jobCounter := 0

	// launch reader
	go func() {
		for {
			select {

			case rpl := <-okChan:
				okStorage.Replys = append(okStorage.Replys, rpl)

			case rpl := <-expires10DaysChan:
				expires10Storage.Replys = append(expires10Storage.Replys, rpl)

			case rpl := <-expires30DaysChan:
				expires30Storage.Replys = append(expires30Storage.Replys, rpl)

			case rpl := <-expires60DaysChan:
				expires60Storage.Replys = append(expires60Storage.Replys, rpl)

			case rpl := <-expiredChan:
				expiredStorage.Replys = append(expiredStorage.Replys, rpl)

			case rpl := <-errorChan:
				errorStorage.Replys = append(errorStorage.Replys, rpl)

			case <-threadCounter:
				jobCounter++
				if jobCounter == numOfDomains {
					printReport <- true
					return
				}
			}
		}
	}()

	// Dummy channel to coordinate the number of concurrent goroutines.
	// This channel should be buffered otherwise we will be immediately blocked
	// when trying to fill it.
	concurrentGoroutines := make(chan struct{}, MaxGoroutines)
	// fill with empty struct
	for i := 0; i < MaxGoroutines; i++ {
		concurrentGoroutines <- struct{}{}
	}

	// Indicate when a single goroutine has finished its job
	done := make(chan bool)
	// Channel allows the main program to wait until we have indeed done all jobs.
	waitForAllJobs := make(chan bool)

	// Collect all the jobs, and since the job is finished, we can release another spot for a goroutine.
	go func() {
		for i := 0; i < numOfDomains; i++ {
			<-done
			// Say that another goroutine can now start.
			concurrentGoroutines <- struct{}{}
		}
		// We have collected all the jobs, the program can now terminate
		waitForAllJobs <- true
		return
	}()

	for i := 1; i <= numOfDomains; i++ {

		if i%100 == 0 {
			Info.Printf("Domains Processed: %d\n", i)
		}

		// Try to receive from the concurrentGoroutines channel
		<-concurrentGoroutines
		go func(idd int) {

			var id int
			var account string
			var domain string
			var checkwhois int
			var checkssl int
			var provider int
			var ssldomain string

			rows.Next()
			err = rows.Scan(&id, &account, &domain, &checkwhois, &checkssl, &provider, &ssldomain)
			CheckErr(err)

			// Info.Printf("Domain:%s,checkwhois:%d,checkssl:%d \n", domain, checkwhois, checkssl)

			var rs ReplyStruct
			rs.ID = id
			rs.Account = account
			rs.Domain = domain
			rs.SlackUser = ""

			var ds DomainStruct
			ds.Account = account
			ds.Domain = domain
			ds.Provider = provider // 0 - whois, 1 - transip api
			ds.SSLDomain = ssldomain

			if checkwhois == 1 {
				GetExpirationDateAsync(ds, 
					rs,
					okChan,
					expires10DaysChan,
					expires30DaysChan,
					expires60DaysChan,
					expiredChan,
					errorChan,
					threadCounter,
					transip_accname, 
					transip_apikey)
			}
			if checkssl == 1 {
				
				go CheckSsl(ds,
					rs,
					okChan,
					expires10DaysChan,
					expires30DaysChan,
					expires60DaysChan,
					expiredChan,
					errorChan,
					threadCounter)
			}

			// tell the reader that the task is done
			done <- true

			return
		}(i)

	}
	<-waitForAllJobs

        rows.Close()
	return
}

func GetSingleExpirationDate(domainAndInfo ReplyStruct, 
	ReplyChan chan<- ReplyStruct, 
	transip_accname string, 
	transip_apikey string, 
	provider string) {

	var ret ReplyStruct
	ret.Domain = domainAndInfo.Domain
	ret.SlackUser = domainAndInfo.SlackUser
	ret.SlackChannel = domainAndInfo.SlackChannel
	ret.MessageType = 1

	var transipDomainRenewalDate = time.Now()

	prov, err := strconv.Atoi(provider)
	if err != nil {
		ret.Error = err

		ReplyChan <- ret
		return
	}

	var result = ""
	
	if prov == 0 {
		result, err = Whois(ret.Domain)
		if err != nil {
			ret.Error = err

			ReplyChan <- ret
			return
		}
    }

	////
	if prov == 1 {
		transipDomainRenewalDate, err = TransipGetRenewalDate(transip_accname, transip_apikey, ret.Domain)
		if err != nil {
			ret.Error = err
	
			ReplyChan <- ret
			return
		}
		
		result, err = TransipGetWhois(transip_accname, transip_apikey, ret.Domain)
		if err != nil {
			ret.Error = err
	
			ReplyChan <- ret
			return
		}
	}
	////

	whoisParserRet, err := whois_parser.Parse(result)
	if err != nil {
		ret.Error = err

		ReplyChan <- ret
		return
	}

	gddval := transipDomainRenewalDate.String() //time.now or actual renewal date
	if prov != 1 {
		gddval = whoisParserRet.Registrar.ExpirationDate
	}

	gdd, isExpiring, expirationTerm, isExpired, err := getDateDiff(gddval)
	if err != nil {
		ret.Error = err

		ReplyChan <- ret
		return
	}

	ret.Date = whoisParserRet.Registrar.ExpirationDate
	ret.ExpirationTerm = expirationTerm
	ret.IsExpiring = isExpiring
	ret.IsExpired = isExpired
	ret.ExpiredDate = gdd

	ReplyChan <- ret
	return
}

func filltempbuf(tempbuf []string , Domain string, Checkwhois string, Checkssl string) string {
    tempbuf = []string{Domain, "check whois:", Checkwhois, "check ssl:", Checkssl}
    return strings.Join(tempbuf, " ")
}

// FindDomain - find domain in db and return all corresponding info
func (env *Env) FindDomain(domainToFind DomainStruct, rpl ReplyStruct, ReplyChan chan<- ReplyStruct) {

	rows, err := env.DB.Query("SELECT id, account, domain, checkwhois, checkssl FROM sites where domain = $1", domainToFind.Domain)
	CheckErr(err)

        var Checkwhois_temp string;
        var Checkssl_temp string; 
        var tempbuf []string;


	for rows.Next() {
		err = rows.Scan(&rpl.ID, &rpl.Account, &rpl.Domain, &Checkwhois_temp, &Checkssl_temp)
		if err != nil {
			rpl.Domain = domainToFind.Domain
			rpl.Error = err

			ReplyChan <- rpl
			Info.Println("err", rpl)
			return
		}
		Info.Println("not err", rpl)
                rpl.Domain = filltempbuf(tempbuf, domainToFind.Domain, Checkwhois_temp, Checkssl_temp)
		ReplyChan <- rpl
	}
        rows.Close()

	return
}

// DeleteDomain - deleting domain from db
func (env *Env) DeleteDomain(delDomain DomainStruct, rpl ReplyStruct, ReplyChan chan<- ReplyStruct) {

	stmt, err := env.DB.Prepare("DELETE FROM sites where domain=?")
	if err != nil {
		rpl.Domain = delDomain.Domain
		rpl.Error = err

		ReplyChan <- rpl
		return
	}

	res, err := stmt.Exec(delDomain.Domain)
	if err != nil {
		rpl.Domain = delDomain.Domain
		rpl.Error = err

		ReplyChan <- rpl
		return
	}

	affect, err := res.RowsAffected()
	if err != nil {
		rpl.Domain = delDomain.Domain
		rpl.Error = err

		ReplyChan <- rpl
		return
	}

	rpl.ID = int(affect)
	rpl.Domain = delDomain.Domain

	ReplyChan <- rpl
	return
}

// AddDomain - adding new domain do database for checks
func (env *Env) AddDomain(domainInfo DomainStruct, userAndChannel ReplyStruct, ReplyChan chan<- ReplyStruct) {

	var rpl ReplyStruct
	rpl.SlackUser = userAndChannel.SlackUser
	rpl.SlackChannel = userAndChannel.SlackChannel
	rpl.MessageType = 2

	stmt, err := env.DB.Prepare(
		"INSERT INTO sites (account, domain, checkwhois, checkssl) values(?,?,?,?)")
	if err != nil {
		rpl.Domain = domainInfo.Domain
		rpl.Error = err

		ReplyChan <- rpl
		return
	}

	res, err := stmt.Exec(domainInfo.Account, domainInfo.Domain, domainInfo.Checkwhois, domainInfo.Checkssl)
	if err != nil {
		rpl.Domain = domainInfo.Domain
		rpl.Error = err

		ReplyChan <- rpl
		return
	}

	id, err := res.LastInsertId()
	if err != nil {
		rpl.Domain = domainInfo.Domain
		rpl.Error = err

		ReplyChan <- rpl
		return
	}

	rpl.ID = int(id)
	rpl.Domain = domainInfo.Domain

	ReplyChan <- rpl
	return
}
