package whoistools

import (
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/nlopes/slack"
)

// RunSlackAndCron ...
func RunSlackAndCron(env *Env,
	allowedUsers []string,
	slackToken string,
	crons []string) {

	api := slack.New(slackToken)

	// broken with last lib update :(
	// slack.SetLogger(Info)
	// api.SetDebug(enabledebug)

	rtm := api.NewRTM()
	go rtm.ManageConnection()

	go startCron(env.DB, allowedUsers[0], rtm, crons)

	threadCounter := make(chan bool)

	ReplyChan := make(chan ReplyStruct, 100)
	go func() {
		for {
			select {
			case <-threadCounter:
				// continue
			case rpl := <-ReplyChan:

				// message types:
				// 1 - reply from GetSingleExpirationDate
				// 2 - reply from AddDomain
				// 3 - reply from DeleteDomain
				// 4 - reply from CheckSsl
				// 5 - reply from FindDomain

				SlackReplyMsg := ""
				SlackReplyErrMsg := ""

				switch rpl.MessageType {
				case 1:
					if rpl.Error != nil {
						SlackReplyErrMsg = "<@" + rpl.SlackUser + "> " +
							rpl.Domain + "\nError: " +
							rpl.Error.Error()
					}
					SlackReplyMsg = "<@" + rpl.SlackUser + "> " +
						rpl.Domain + "\nExpiration Date: " +
						rpl.Date + "\nFirst Notice: " +
						rpl.ExpiredDate.String() + "\nExpiration Term Level: " +
						strconv.Itoa(rpl.ExpirationTerm)

				case 2:
					if rpl.Error != nil {
						SlackReplyErrMsg = "<@" + rpl.SlackUser + "> " +
							rpl.Domain + "\nError: " +
							rpl.Error.Error()
					}
					SlackReplyMsg = "<@" + rpl.SlackUser + "> " +
						rpl.Domain + " added\nId:" +
						strconv.Itoa(rpl.ID)

				case 3:
					if rpl.Error != nil {
						SlackReplyErrMsg = "<@" + rpl.SlackUser + "> " +
							rpl.Domain + "\ndeletion error: " +
							rpl.Error.Error()
					}
					SlackReplyMsg = "<@" + rpl.SlackUser + "> records containing domain " +
						rpl.Domain + " deleted\naffected rows:" +
						strconv.Itoa(rpl.ID)

				case 4:
					if rpl.Error != nil {
						SlackReplyErrMsg = "<@" + rpl.SlackUser + "> " +
							rpl.Domain + "\nSsl check error: " +
							rpl.Error.Error()
					} else if rpl.IsExpired {
						SlackReplyMsg = "<@" + rpl.SlackUser + "> " +
							rpl.Domain + "\nSsl expired: " +
							rpl.Date
					} else if rpl.IsExpiring {
						SlackReplyMsg = "<@" + rpl.SlackUser + "> " +
							rpl.Domain + "\nSsl expiring level: " +
							strconv.Itoa(rpl.ExpirationTerm) + " \nExpiration date: " +
							rpl.Date
					} else {
						SlackReplyMsg = "<@" + rpl.SlackUser + ">  " +
							rpl.Domain + " is ok\nIssuer: " +
							rpl.SslIssuer + "\nValid untill: " +
							rpl.ExpiredDate.String() + "\nFirst notice: " +
							rpl.Date
					}

				case 5:
					if rpl.Error != nil {
						SlackReplyErrMsg = "<@" + rpl.SlackUser + "> " +
							rpl.Domain + "\nFind error: " +
							rpl.Error.Error()
					} else {
						SlackReplyMsg = "<@" + rpl.SlackUser + ">  " +
							strconv.Itoa(rpl.ID) + "\n" +
							rpl.Domain + "\n" +
							rpl.Account + "\n"

					}

				default:
					SlackReplyErrMsg = "Unrecognsed MessageType for error"
					SlackReplyMsg = "Unrecognsed MessageType for reply"

				}

				SlackRpl := "SlackRpl PLACEHOLDER"
				if rpl.Error != nil {
					SlackRpl = SlackReplyErrMsg
				} else {
					SlackRpl = SlackReplyMsg
				}

				// Info.Println(rpl)
				rtm.SendMessage(rtm.NewOutgoingMessage(
					SlackRpl,
					rpl.SlackChannel))
			}
		}
	}()

	// simpleDomainRegex := regexp.MustCompile(`([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+?\.[a-zA-Z]{2,11}`)
	domainRegex := regexp.MustCompile(`([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}(:[0-9]{1,5})?`)

	for msg := range rtm.IncomingEvents {
		switch ev := msg.Data.(type) {
		case *slack.HelloEvent:
			//          fmt.Printf("ID: %s, Fullname: %s, Email: %s\n", user.ID, user.Profile.RealName, user.Profile.Email)

		case *slack.ConnectedEvent:
			//			fmt.Println("Infos:", ev.Info)
			//			fmt.Println("Connection counter:", ev.ConnectionCount)
			// Replace C2147483705 with your SlackChannel ID
			//rtm.SendMessage(rtm.NewOutgoingMessage("Domain whois check bot connected", allowedUsers[0]))

		case *slack.MessageEvent:
			// Info.Printf("ev.SlackChannel: %s, ev.Msg: %v, ev.Text: %s, ev.SubMessage: %v, ev.Comment:%s ",
			// ev.Channel, ev.Msg, ev.Text, ev.SubMessage, ev.Comment)

			if !checkPrivileges(ev.User, allowedUsers) {
				// rtm.SendMessage(rtm.NewOutgoingMessage(
				// "<@"+ev.User+"> Sorry, you're not allowed to send commands", ev.Channel))
				log.Println("<@"+ev.User+"> Sorry, you're not allowed to send commands", ev.Channel)
				break

			}

			switch {
			case strings.Contains(ev.Text, "checkwhois"):
				matches := domainRegex.FindString(ev.Text)

				var rs ReplyStruct
				rs.Domain, rs.SlackUser, rs.SlackChannel = matches, ev.User, ev.Channel

				go GetSingleExpirationDate(rs, ReplyChan)

			case strings.Contains(ev.Text, "checkssl"):
				matches := domainRegex.FindString(ev.Text)
				var rs ReplyStruct

				rs.Domain = matches
				rs.SlackUser = ev.User
				rs.SlackChannel = ev.Channel
				rs.Account = ""

				go CheckSsl(rs, ReplyChan, ReplyChan, ReplyChan, ReplyChan, ReplyChan, ReplyChan, "")

			case strings.Contains(ev.Text, "fullexpirationlist"):
				// go FEL(db, allowedUsers[0], *rtm)
				go (*Env).FEL(env, allowedUsers[0], *rtm)

			case strings.Contains(ev.Text, "adddomain"):
				matches := domainRegex.FindString(ev.Text)
				ss := strings.Split(ev.Text, ",")

				var rs ReplyStruct
				rs.SlackUser = ev.User
				rs.SlackChannel = ev.Channel
				rs.MessageType = 2

				if len(ss) < 4 || len(ss) > 4 {
					rs.Error = errors.New("Err args len:" + strconv.Itoa(len(ss)))
					ReplyChan <- rs
					break
				}

				addDom := DomainStruct{ID: 0, Account: ss[1], Domain: matches, Checkwhois: ss[2], Checkssl: ss[3]}
				go (*Env).AddDomain(env, addDom, rs, ReplyChan)

			case strings.Contains(ev.Text, "finddomain"):
				matches := domainRegex.FindString(ev.Text)
				findDomain := DomainStruct{ID: 0, Account: "", Domain: matches, Checkwhois: "", Checkssl: ""}

				var rs ReplyStruct
				rs.SlackUser = ev.User
				rs.SlackChannel = ev.Channel
				rs.MessageType = 5

				go (*Env).FindDomain(env, findDomain, rs, ReplyChan)

			case strings.Contains(ev.Text, "deldomain"):
				matches := domainRegex.FindString(ev.Text)
				delDom := DomainStruct{ID: 0, Account: "", Domain: matches, Checkwhois: "", Checkssl: ""}

				var rpl ReplyStruct
				rpl.SlackUser = ev.User
				rpl.SlackChannel = ev.Channel
				rpl.MessageType = 3

				go (*Env).DeleteDomain(env, delDom, rpl, ReplyChan)

			case strings.Contains(ev.Text, "help"):
				helpMessageList := "\ncheckwhois <domain|string> - for checking one site\n" +
					"fullexpirationlist - for checking all sites in db (may take minutes in you have hundreds of domains)\n" +
					"adddomain <domain|string>,<account|string>,<checkwhois|bool(0,1)>,<checkssl|bool(0,1)> - adddomain example.com,Robert Paulson 123456,1,1\n" +
					"deldomain <domain> - deldomain example.com\n" +
					"checkssl <domain>:<port> - checkssl example.com:443\n" +
					"finddomain <domain> - finddomain example.com\n"
				rtm.SendMessage(rtm.NewOutgoingMessage("<@"+ev.User+"> "+helpMessageList, ev.Channel))

			default:

			}

		case *slack.PresenceChangeEvent:
			fmt.Printf("Presence Change: %v\n", ev)

			//case *slack.LatencyReport:
			//fmt.Printf("Current latency: %v\n", ev.Value)

		case *slack.RTMError:
			Info.Printf("Error: %s\n", ev.Error())

		case *slack.InvalidAuthEvent:
			Info.Printf("Invalid credentials")

		default:
			//fmt.Printf("Unexpected: %v\n", msg.Data)
		}
	}

}
