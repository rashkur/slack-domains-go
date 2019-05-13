# whois-go
 Slack bot for checking domains and ssl certificates for expiration 
 
![Main Window](https://i.imgur.com/1TbqKHo.png)

## Why?

I've had a big pool of domains on my work (500+) and checking 3-4 godaddy accounts and emails was a boring routine for me. So I'd wrote this bot to to automate it.
Later I've added ssl checking support with port costumization. 

## How to use it?

* Download release or compile in by yourself (linux kernel 3.6+ needed).
* Fill the bot.ini and run it. If you dont know you slack ID just type 'help' into the channel and check the console. You'll have message like ```<@UXXXXXXXX> Sorry, you're not allowed to send commands...```. This is your id. Copy and past it to the config without @ symbol. 
* Bot will automatically create sqlite database file in the working directory.
* Send 'help' to your slack channel with bot and start adding domains via slack bot channel. You will see message like ```checkwhois <domain|string> - for checking one site

fullexpirationlist - for checking all sites in db (may take minutes in you have hundreds of domains)

adddomain <domain|string>,<account|string>,<checkwhois|bool(0,1)>,<checkssl|bool(0,1)> - adddomain example.com,Robert Paulson 123456,1,1

deldomain <domain> - deldomain example.com
 
checkssl <domain>:<port> - checkssl example.com:443
 
finddomain <domain> - finddomain example.com```

## 3rd party code
Partially use code from github.com/likexian/whois-parser-go to parse whois data. 
