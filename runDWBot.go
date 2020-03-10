package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"

	"./whoisTools"
	ini "gopkg.in/ini.v1"
)

var (
	slackToken   = ""
	allowedUsers = []string{}
	crons        = []string{}
	debug		 = false
	transip_accname = ""
	transip_apikey = ""
	dbPath       = "./dwbot.sqlite"
	createTmpl   = "CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY, account TEXT, domain TEXT NOT NULL CHECK (domain <> ''), checkwhois TINYINT, checkssl TINYINT, provider INTEGER NOT NULL, ssldomain TEXT NOT NULL)"
)

func main() {

	cfg, err := ini.Load("bot.ini")
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
		os.Exit(1)
	}

	slackToken = cfg.Section("slack").Key("slack_token").String()
	allowedUsers = strings.Split(cfg.Section("slack").Key("allowed_users").String(), ",")
	crons = strings.Split(cfg.Section("bot").Key("crons").String(), ",")
	debug = cfg.Section("app").Key("debug").MustBool(false)

	transip_accname = cfg.Section("transip").Key("accname").String()
	transip_apikey = cfg.Section("transip").Key("apikey").String()

	whoistools.InitLog(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr, os.Stdout)
	whoistools.Info.Println("Domain whois bot started")

	runtime.GOMAXPROCS(whoistools.GetHalfOfCpuThreads())

	env := whoistools.InitDb(dbPath, createTmpl)

	// running slackbot and cronjobs
	whoistools.RunSlackAndCron(env, allowedUsers, slackToken, crons, debug, transip_accname, transip_apikey)
}
