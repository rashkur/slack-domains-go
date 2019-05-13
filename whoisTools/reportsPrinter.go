package whoistools

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"text/tabwriter"

	"github.com/nlopes/slack"
)

// if len>cap - use snippet
const sizeCap = 25

type wrt []byte

func (w *wrt) Write(b []byte) (int, error) {
	*w = append(*w, b...)
	return len(b), nil
}

// format messages before sending
func messageFormatter(replyStorage *WhoisReplys, prefix string, postfix string) string {

	// quick one for sorted by domain name output
	var temp = *replyStorage
	sort.Sort(DomainSorted(temp))

	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 8, 2, ' ', 0)

	if len(prefix) > 0 {
		fmt.Fprintln(w, prefix)
	}
	for i := 0; i < len(temp.Replys); i++ {
		switch temp.Replys[i].Error {
		case nil:
			replyString := temp.Replys[i].Domain + "\t" +
				temp.Replys[i].ExpiredDate.String() + "\t" +
				temp.Replys[i].Account + "\t"

			fmt.Fprintln(w, replyString)
		default:
			replyString := temp.Replys[i].Domain + "\t" +
				temp.Replys[i].Account + "\t" +
				temp.Replys[i].Error.Error() + "\t"

			fmt.Fprintln(w, replyString)
		}
	}
	if len(postfix) > 0 {
		fmt.Fprintln(w, postfix)
	}

	w.Flush()
	return b.String()
	//b.Reset()
}

// SendFileToSlack - https://github.com/nlopes/slack/blob/master/files_test.go
func sendFileToSlack(filename string, content string, slackChannel string, rtm slack.RTM) {
	params := slack.FileUploadParameters{
		Filename: filename, Content: content,
		Channels: []string{slackChannel}}
	if _, err := rtm.UploadFile(params); err != nil {
		// log.Printf("Unexpected error: %s", err)
		rtm.SendMessage(rtm.NewOutgoingMessage(err.Error(), slackChannel))
	}
}

// send short message as a message and long as a snippet
func separator(storage *WhoisReplys, filename string, prefix string, postfix string, slackChannel string, rtm slack.RTM) {
	//we only need to know count for ok
	if filename == "Ok" {
		rtm.SendMessage(rtm.NewOutgoingMessage("```Ok: "+strconv.Itoa(len(storage.Replys))+" domains```", slackChannel))
		return
	}

	if len(storage.Replys) <= sizeCap {
		rtm.SendMessage(rtm.NewOutgoingMessage(messageFormatter(storage, prefix, postfix), slackChannel))
		return
	}

	if len(storage.Replys) > sizeCap {
		//ignoring prefix and postfix for files
		sendFileToSlack(filename+".txt", messageFormatter(storage, "", ""), slackChannel, rtm)
		return
	}
}

// PrintReport using for printing reports back to bot's slack channel
func PrintReport(rtm slack.RTM,
	printReport <-chan bool,
	slackChannel string,
	okStorage *WhoisReplys,
	expires10Storage *WhoisReplys,
	expires30Storage *WhoisReplys,
	expires60Storage *WhoisReplys,
	expiredStorage *WhoisReplys,
	errorStorage *WhoisReplys) {

	for {
		select {
		case <-printReport:
			separator(okStorage, "Ok", "```Ok:", "```", slackChannel, rtm)
			separator(expires10Storage, "ExpiresIn10Days", "```In 10 days:", "```", slackChannel, rtm)
			separator(expires30Storage, "ExpiresIn30Days", "```In 30 days:", "```", slackChannel, rtm)
			separator(expires60Storage, "ExpiresIn60Days", "```In 60 days:", "```", slackChannel, rtm)
			separator(expiredStorage, "Expired", "```Expired:", "```", slackChannel, rtm)
			separator(errorStorage, "Errors", "```Errors:", "```", slackChannel, rtm)
			return
		}
	}
}
