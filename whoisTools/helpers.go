package whoistools

import (
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/araddon/dateparse"
)

var (
	expirationTermsArr = []int{Next10DaysExpiration, Next30DaysExpiration, Next60DaysExpiration}
	ambigousFormats    = []string{"2006. 01. 02.", "02-Jan-2006"}
)

func CheckErr(err error) {
	if err != nil {
		Error.Println(err.Error())
		// os.Exit(100)
	}
}

func checkPrivileges(user string, allowedUsers []string) bool {
	for _, v := range allowedUsers {
		if v == user {
			return true
		}
	}
	return false
}

func GetHalfOfCpuThreads() int {
	numcpu := runtime.NumCPU()
	if numcpu > 1 {
		numcpu = numcpu / 2
	}
	return numcpu
}

func dateParser(dateToParse string) (parsedDate time.Time, err error) {
	timeNow := time.Now()
	time.Local = timeNow.Location()
	if err != nil {
		return timeNow, err
	}

	if dateToParse == "" {
		return timeNow, errors.New("Cannot parse empty date")
	}

	parsedDate, err = dateparse.ParseLocal(dateToParse)
	if err != nil {
		for i := range ambigousFormats {
			t, err := time.Parse(ambigousFormats[i], dateToParse)
			if err == nil {
				return t, err
			}
		}
		return timeNow, err
	}
	return parsedDate, err
}

func getDateDiff(
	dateToParse interface{}) (
	parsedTime time.Time,
	isExpiring bool,
	expirationTerm int,
	isExpired bool,
	err error) {

	timeNow := time.Now()

	switch dtp := dateToParse.(type) {
	case string:
		parsedTime, err = dateParser(dtp)
	case time.Time:
		parsedTime = dtp
	default:
		return timeNow, false, 0, false, errors.New("date interface error")
	}

	// Info.Println("getDateDiff paresd test:", parsedTime)

	if err != nil {
		return parsedTime, false, 0, false, err
	}

	// extracting time from domain expiration date to check is it ok,
	// expiring or already expired

	// checking if domain already expired ...
	if parsedTime.Before(timeNow) {
		return parsedTime, false, 0, true, err
	}

	// ...or will be expired soon
	for expirationTerm := 0; expirationTerm < len(expirationTermsArr); expirationTerm++ {
		expiration := parsedTime.AddDate(0, 0, expirationTermsArr[expirationTerm])

		if expiration.Before(timeNow) {
			return parsedTime, true, expirationTermsArr[expirationTerm], false, err
		}
	}
	return parsedTime.AddDate(0, 0, Next60DaysExpiration), false, 0, false, err
}

// sorting output for reports printer
func (a DomainSorted) Len() int      { return len(a.Replys) }
func (a DomainSorted) Swap(i, j int) { a.Replys[i], a.Replys[j] = a.Replys[j], a.Replys[i] }
func (a DomainSorted) Less(i, j int) bool {
	return strings.ToLower(a.Replys[i].Domain) < strings.ToLower(a.Replys[j].Domain)
}
