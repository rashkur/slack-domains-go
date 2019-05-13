package whoistools

import (
	"time"
)

const (
	MaxGoroutines                                                    = 4
	Next10DaysExpiration, Next30DaysExpiration, Next60DaysExpiration = -10, -30, -60
)

type DomainStruct struct {
	ID         int
	Domain     string
	Account    string
	Checkwhois string
	Checkssl   string
}

type WhoisReplys struct {
	Replys []ReplyStruct
}

type DomainSorted WhoisReplys

type ReplyStruct struct {
	ID             int
	Account        string
	Error          error
	Domain         string
	Server         string
	Date           string
	IsExpiring     bool
	ExpirationTerm int
	IsExpired      bool
	ExpiredDate    time.Time
	SlackUser      string
	SlackChannel   string
	SslIssuer      string
	MessageType    int
}
