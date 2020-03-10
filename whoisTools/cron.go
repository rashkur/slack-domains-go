package whoistools

import (
	"database/sql"

	"github.com/slack-go/slack"
	"github.com/robfig/cron"
)

func startCron(db *sql.DB, 
	slackChannel string, 
	rtm *slack.RTM, 
	crons []string,
	transip_accname string, 
	transip_apikey string) {
	c := cron.New()
	env := &Env{DB: db}
	for _, cron := range crons {
		c.AddFunc(cron, func() { (*Env).FEL(env, slackChannel, *rtm, transip_accname, transip_apikey) })
	}
	c.Start()
}
