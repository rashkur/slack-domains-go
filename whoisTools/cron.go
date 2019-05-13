package whoistools

import (
	"database/sql"

	"github.com/nlopes/slack"
	"github.com/robfig/cron"
)

func startCron(db *sql.DB, slackChannel string, rtm *slack.RTM, crons []string) {
	c := cron.New()
	env := &Env{DB: db}
	for _, cron := range crons {
		c.AddFunc(cron, func() { (*Env).FEL(env, slackChannel, *rtm) })
	}
	c.Start()
}
