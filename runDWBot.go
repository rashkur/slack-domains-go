package main

import (
	//"github.com/likexian/whois-parser-go"

	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"

	"./whoisTools"
	ini "gopkg.in/ini.v1"
	// _ "github.com/mattn/go-sqlite3"
)

var (
	// first array item - channel for reports printing with cron
	// bot channel, rashkur, max, medianyk
	// when to check domains from db

	slackToken   = ""
	allowedUsers = []string{}
	crons        = []string{}
	dbPath       = "./dwbot.db"
	createTmpl   = "CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY, account TEXT, domain TEXT NOT NULL CHECK (domain <> ''), checkwhois TINYINT, checkssl TINYINT)"
)

func main() {

	cfg, err := ini.Load("bot.ini")
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
		os.Exit(1)
	}

	slackToken = cfg.Section("slack").Key("slack-token").String()
	allowedUsers = strings.Split(cfg.Section("slack").Key("allowed-users").String(), ",")
	crons = strings.Split(cfg.Section("bot").Key("crons").String(), ",")

	whoistools.InitLog(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr, os.Stdout)
	whoistools.Info.Println("Domain whois bot started")

	runtime.GOMAXPROCS(whoistools.GetHalfOfCpuThreads())

	env := whoistools.InitDb(dbPath, createTmpl)

	// running slackbot and cronjobs
	whoistools.RunSlackAndCron(env, allowedUsers, slackToken, crons)
}
