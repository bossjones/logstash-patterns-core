# get date

Given: `Apr  7 18:56:11 ubnt kernel: [LAN_LOCAL-default-A]IN=eth0 OUT= MAC=64:ad:d9:1b:b8:09:68:c7:9n:23:fa:f8:09:00 SRC=192.168.1.18 DST=192.168.1.1 LEN=63 TOS=0x00 PREC=0x00 TTL=64 ID=46017 DF PROTO=UDP SPT=60561 DPT=53 LEN=43`

```
{job="rsyslogng"} |~ ".*kernel.*" | regexp `^(?P<month>(\b(?:[Jj]an(?:uary|uar)?|[Ff]eb(?:ruary|ruar)?|[Mm](?:a|ä)?r(?:ch|z)?|[Aa]pr(?:il)?|[Mm]a(?:y|i)?|[Jj]un(?:e|i)?|[Jj]ul(?:y)?|[Aa]ug(?:ust)?|[Ss]ep(?:tember)?|[Oo](?:c|k)?t(?:ober)?|[Nn]ov(?:ember)?|[Dd]e(?:c|z)(?:ember)?)\b))(\s*)(?P<daynum>(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])) (?P<time>(((<[0-9])?)((?:2[0123]|[01]?[0-9])):((?:[0-5][0-9]))(?::((?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)))(([0-9])?)))(\s*)(?P<hostname>(\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)))(\s*)(?:(\s*))?((?P<process_name>\b\w+\b):)(?:(\s*))?`
```