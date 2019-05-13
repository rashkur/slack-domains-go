package whoistools

import (
	"../whois-parser-go"
	"github.com/nlopes/slack"
)

func (env *Env) FEL(slackChannel string, rtm slack.RTM) {
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

	// jobCounter := 0

	// full expiration reports printer
	(*Env).FullExpirationList(env,
		&okStorage,
		&expires10Storage,
		&expires30Storage,
		&expires60Storage,
		&expiredStorage,
		&errorStorage,
		printReportsSignal)

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
	rs ReplyStruct,
	okChan chan<- ReplyStruct,
	expires10DaysChan chan<- ReplyStruct,
	expires30DaysChan chan<- ReplyStruct,
	expires60DaysChan chan<- ReplyStruct,
	expiredChan chan<- ReplyStruct,
	errorChan chan<- ReplyStruct,
	threadCounter chan<- bool) {

	var ret ReplyStruct
	ret.ID = rs.ID
	ret.Domain = rs.Domain
	ret.Account = rs.Account
	ret.SlackUser = rs.SlackUser
	ret.SlackChannel = rs.SlackChannel
	ret.Server = rs.Server

	// all domains with invalid whois going to error channel
	result, err := Whois(rs.Domain)
	if err != nil {
		ret.Error = err

		errorChan <- ret
		threadCounter <- true
		return
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

	gdd, isExpiring, expirationTerm, isExpired, err := getDateDiff(whoisParserRet.Registrar.ExpirationDate)
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
	printReport chan<- bool) {

	//get total amount of domains
	rows, err := env.DB.Query("SELECT COUNT(*) FROM sites WHERE checkwhois=1 OR checkssl=1")
	CheckErr(err)
	var numOfDomains int
	for rows.Next() {
		err = rows.Scan(&numOfDomains)
		CheckErr(err)
	}
	// get all records in loop and run check
	rows, err = env.DB.Query("SELECT * FROM sites WHERE checkwhois=1 OR checkssl=1 ORDER BY RANDOM()")
	// numOfDomains = 100
	// rows, err = env.DB.Query("SELECT * FROM sites WHERE checkwhois=1 OR checkssl=1 ORDER BY RANDOM() LIMIT 100")
	CheckErr(err)

	var id int
	var account string
	var domain string
	var checkwhois int
	var checkssl int
	var server string

	// jobUUID := uuid.Must(uuid.NewV4())

	okChan := make(chan ReplyStruct, 100)
	expires10DaysChan := make(chan ReplyStruct, 100)
	expires30DaysChan := make(chan ReplyStruct, 100)
	expires60DaysChan := make(chan ReplyStruct, 100)
	expiredChan := make(chan ReplyStruct, 100)
	errorChan := make(chan ReplyStruct, 100)

	// printReport := make(chan bool)
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
					//exit
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
		//exit
		return
	}()

	for i := 1; i <= numOfDomains; i++ {

		if i%100 == 0 {
			Info.Printf("Domains Processed: %d\n", i)
		}

		// Try to receive from the concurrentGoroutines channel
		<-concurrentGoroutines
		go func(idd int) {
			rows.Next()
			err = rows.Scan(&id, &account, &domain, &checkwhois, &checkssl)
			CheckErr(err)

			var rs ReplyStruct
			rs.ID = id
			rs.Account = account
			rs.Domain = domain
			rs.Server = server
			rs.SlackUser = ""
			// rs.SlackChannel = slackChannel

			//Info.Println(rs.Domain)

			if checkwhois == 1 {
				GetExpirationDateAsync(rs,
					okChan,
					expires10DaysChan,
					expires30DaysChan,
					expires60DaysChan,
					expiredChan,
					errorChan,
					threadCounter)
			}
			if checkssl == 1 {

				go CheckSsl(rs,
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

	return
}

func GetSingleExpirationDate(domainAndInfo ReplyStruct, ReplyChan chan<- ReplyStruct) {
	var ret ReplyStruct
	ret.Domain = domainAndInfo.Domain
	ret.SlackUser = domainAndInfo.SlackUser
	ret.SlackChannel = domainAndInfo.SlackChannel
	ret.MessageType = 1

	result, err := Whois(ret.Domain)
	if err != nil {
		ret.Error = err

		ReplyChan <- ret
		return
	}

	res, err := whois_parser.Parse(result)
	if err != nil {
		ret.Error = err

		ReplyChan <- ret
		return
	}

	gdd, isExpiring, expirationTerm, isExpired, err := getDateDiff(res.Registrar.ExpirationDate)
	if err != nil {
		ret.Error = err

		ReplyChan <- ret
		return
	}

	ret.Date = res.Registrar.ExpirationDate
	ret.ExpirationTerm = expirationTerm
	ret.IsExpiring = isExpiring
	ret.IsExpired = isExpired
	ret.ExpiredDate = gdd

	ReplyChan <- ret
	return
}

// FindDomain - find domain in db and return all corresponding info
func (env *Env) FindDomain(domainToFind DomainStruct, rpl ReplyStruct, ReplyChan chan<- ReplyStruct) {

	rows, err := env.DB.Query("SELECT id, account, domain FROM sites where domain = $1", domainToFind.Domain)
	CheckErr(err)

	for rows.Next() {
		err = rows.Scan(&rpl.ID, &rpl.Account, &rpl.Domain)
		if err != nil {
			rpl.Domain = domainToFind.Domain
			rpl.Error = err

			ReplyChan <- rpl
			Info.Println("err", rpl)
			return
		}
		Info.Println("not err", rpl)
		ReplyChan <- rpl
	}

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
