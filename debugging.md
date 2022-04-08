./grok-to-regex.py "%{BOSSJONES_IPTABLES_IP_START}"
./grok-to-regex.py "%{IPV4}"
./grok-to-regex.py "%{UNSIGNED_INT}"
./grok-to-regex.py "%{BASE16NUM}"
./grok-to-regex.py "%{WORD}"
./grok-to-regex.py "%{INT}"
./grok-to-regex.py "%{GREEDYDATA}"

# rule in grok
BOSS_UNIFI_IPTABLES_SECURITY_GATEWAY \A%{SYSLOGTIMESTAMP:timestamp_logged}%{SPACE}%{SYSLOGHOST:hostname}%{SPACE}%{WORD:programname}%{NOTSPACE}%{SPACE}\[%{WORD:iptables.interface}-%{WORD:iptables.rule_index}-%{UBIQUITI_FIELD:iptables.rule_action}\]%{UBIQUITI_FIELD_IPTABLES_RULE_SET:iptables.rule_set}
BOSS_UNIFI_IPTABLES_LOG_RULES %{SYSLOGTIMESTAMP:timestamp_logged}%{SPACE}%{BACULA_DEVICE}%{SPACE}%{BACULA_JOB}%{NOTSPACE}%{SPACE}\[%{WORD:iptables.interface}-%{WORD:iptables.rule_index}-%{UBIQUITI_FIELD:iptables.rule_action}\]%{UBIQUITI_FIELD_IPTABLES_RULE_SET}

# the whole ip rule, intermediate
((IN=(?P<in_device>\b\w+\b)? OUT=(?P<out_device>\b\w+\b)?(?: MAC=(?P<mac>(?:%{MAC}:%{MAC}:%{ETHTYPE}?((?::[A-Fa-f0-9]{2})*)|%{MAC}((?::[A-Fa-f0-9]{2})*):%{ETHTYPE}?)))?) ((SRC=(?P<src_ip>(?:(((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?)|((?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])))) DST=(?P<dst_ip>(?:(((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?)|((?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])))) LEN=(?P<length>[0-9]+) TOS=0x(?P<tos>(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))) PREC=0x(?P<prec>(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))) TTL=(?P<ttl>[0-9]+) ID=(?P<id>[0-9]+)(?: (?P<fragment_flags>((?<= )(CE|DF|MF))*))?(?: FRAG: (?P<fragment>[0-9]+))?) ((PROTO=((?P<proto>\b\w+\b)))( (SPT=(?P<src_port>[0-9]+) DPT=(?P<dst_port>[0-9]+)))?( (((?:(SEQ=(?P<seq_seq>[0-9]+) ACK=(?P<seq_ack>[0-9]+)) )?WINDOW=(?P<window>[0-9]+) RES=0x(?P<res>(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))) (?P<tcp_flags>((?<= )(CWR|ECE|URG|ACK|PSH|RST|SYN|FIN))*))|(LEN=(?P<udp_len>[0-9]+))|(TYPE=(?P<icmp_type>[0-9]+) CODE=(?P<icmp_code>[0-9]+)(( (INCOMPLETE \[(?P<incomplete>[0-9]+) bytes\]))|(( (?:(ID=%{UNSIGNED_INT} SEQ=%{UNSIGNED_INT})|(PARAMETER=%{UNSIGNED_INT})|(GATEWAY=%{IP})))*)))|(INCOMPLETE \[(?P<incomplete>[0-9]+) bytes\])))?)))

# rule in regex
(\A(?P<timestamp_logged>(\b(?:[Jj]an(?:uary|uar)?|[Ff]eb(?:ruary|ruar)?|[Mm](?:a|ä)?r(?:ch|z)?|[Aa]pr(?:il)?|[Mm]a(?:y|i)?|[Jj]un(?:e|i)?|[Jj]ul(?:y)?|[Aa]ug(?:ust)?|[Ss]ep(?:tember)?|[Oo](?:c|k)?t(?:ober)?|[Nn]ov(?:ember)?|[Dd]e(?:c|z)(?:ember)?)\b) +((?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])) ((?!<[0-9])((?:2[0123]|[01]?[0-9])):((?:[0-5][0-9]))(?::((?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)))(?![0-9])))(\s*)(?P<hostname>((?:((?:(((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?)|((?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9]))))|(\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)))))(\s*)(?P<programname>\b\w+\b)(\S+)(\s*)\[%{WORD:iptables.interface}-%{WORD:iptables.rule_index}-%{UBIQUITI_FIELD:iptables.rule_action}\]%{UBIQUITI_FIELD_IPTABLES_RULE_SET:iptables.rule_set})




(SRC=%{IPV4:firewall.source.ip} DST=%{IPV4:firewall.destination.ip} LEN=%{UNSIGNED_INT:firewall.packet_length} TOS=0x%{BASE16NUM:firewall.tos} PREC=0x%{BASE16NUM:firewall.precidence_field} TTL=%{UNSIGNED_INT:firewall.ttl} ID=%{UNSIGNED_INT:firewall.id}(?:(\s*))?(?:%{WORD:firewall.dont_fragment})?(?:(\s*))?PROTO=%{WORD:firewall.nf_protocol} SPT=%{INT:firewall.spt} DPT=%{INT:firewall.dtp} %{GREEDYDATA:firewall.tcp_opts})
((?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9]))
([0-9]+)
((?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+)))
(\b\w+\b)
((?:[+-]?(?:[0-9]+)))
(.*)


# given: Apr  7 18:56:11 ubnt kernel: [LAN_LOCAL-default-A]IN=eth0 OUT= MAC=64:ad:d9:1b:b8:09:68:c7:9n:23:fa:f8:09:00 SRC=192.168.1.18 DST=192.168.1.1 LEN=63 TOS=0x00 PREC=0x00 TTL=64 ID=46017 DF PROTO=UDP SPT=60561 DPT=53 LEN=43
# Building out pattern
^(?<month>(\b(?:[Jj]an(?:uary|uar)?|[Ff]eb(?:ruary|ruar)?|[Mm](?:a|ä)?r(?:ch|z)?|[Aa]pr(?:il)?|[Mm]a(?:y|i)?|[Jj]un(?:e|i)?|[Jj]ul(?:y)?|[Aa]ug(?:ust)?|[Ss]ep(?:tember)?|[Oo](?:c|k)?t(?:ober)?|[Nn]ov(?:ember)?|[Dd]e(?:c|z)(?:ember)?)\b))


# Expanded

```
<filter unifi.syslog.**>
      @type parser
      @id iptables_security_gateway_logs
      key_name message
      reserve_data true
      reserve_time true
      # remove_key_name_field true
      <parse>
        @type grok
        custom_pattern_path /grok.d
        grok_failure_key grokfailure
        # WITHOUT IDS BLOCK

        <grok>
          pattern (?:%{SPACE})?%{BOSSJONES_UNIFI_PROCESS_NAME}(?:%{SPACE})?(?:%{BOSSJONES_UNIFI_SECURITYGATEWAY_FIREWALL_LOGS})(?:%{BOSSJONES_UNIFI_SECURITYGATEWAY_FIREWALL_LOGS})?(?:%{SPACE})?(?:%{BOSSJONES_UNIFI_SECURITYGATEWAY_FIREWALL_IPTABLES_ETHERNET}|%{BOSSJONES_IPTABLES_IP_START})? (?:%{BOSSJONES_IPTABLES_IP_START})?
        </grok>
        # IDS BLOCK
        # EG. Apr 17 21:10:16 UniFiSecurityGateway3P kernel: ALIEN BLOCK: IN=eth0 OUT=eth1 MAC=ff:ff:f2:fe:f0:fc:00:0f:29:08:ff:f2:08:00 SRC=46.246.123.145 DST=192.168.1.24 LEN=29 TOS=0x00 PREC=0x00 TTL=49 ID=4452 DF PROTO=UDP SPT=8888 DPT=60156 LEN=9
        <grok>
          pattern (?:%{SPACE})?%{BOSSJONES_UNIFI_PROCESS_NAME}(?:%{SPACE})?(?:%{BOSSJONES_UNIFI_SECURITYGATEWAY_FIREWALL_LOGS})?%{BOSSJONES_UNIFI_SECURITYGATEWAY_IDS_LOGS_START}(?:%{BOSSJONES_UNIFI_SECURITYGATEWAY_FIREWALL_LOGS})?(?:%{SPACE})?(?:%{BOSSJONES_UNIFI_SECURITYGATEWAY_FIREWALL_IPTABLES_ETHERNET}|%{BOSSJONES_IPTABLES_IP_START})? (?:%{BOSSJONES_IPTABLES_IP_START})?
        </grok>
        # IN= then SRC=
        # EG. kernel: [LAN_LOCAL-default-A]IN=eth1 OUT= MAC=ff:ff:f2:fe:f0:fc:00:0f:29:08:ff:f2:08:00 SRC=192.168.1.172 DST=192.168.1.1 LEN=119 TOS=0x00 PREC=0x00 TTL=63 ID=21542 DF PROTO=UDP SPT=5432 DPT=53 LEN=99
        <grok>
          pattern (?:%{SPACE})?%{BOSSJONES_UNIFI_PROCESS_NAME}(?:%{SPACE})?(?:%{BOSSJONES_UNIFI_SECURITYGATEWAY_FIREWALL_LOGS})?(?:%{BOSSJONES_UNIFI_SECURITYGATEWAY_FIREWALL_LOGS})?(?:%{SPACE})?%{BOSSJONES_UNIFI_SECURITYGATEWAY_FIREWALL_IPTABLES_ETHERNET} (?:%{BOSSJONES_IPTABLES_IP_START})?
        </grok>
        <grok>
          pattern %{GREEDYDATA:raw_log}
        </grok>
      </parse>
    </filter>
```

## WITHOUT IDS BLOCK

```
# grok

^(?P<month>(\b(?:[Jj]an(?:uary|uar)?|[Ff]eb(?:ruary|ruar)?|[Mm](?:a|ä)?r(?:ch|z)?|[Aa]pr(?:il)?|[Mm]a(?:y|i)?|[Jj]un(?:e|i)?|[Jj]ul(?:y)?|[Aa]ug(?:ust)?|[Ss]ep(?:tember)?|[Oo](?:c|k)?t(?:ober)?|[Nn]ov(?:ember)?|[Dd]e(?:c|z)(?:ember)?)\b))(\s*)(?P<daynum>(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])) (?P<time>((?!<[0-9])((?:2[0123]|[01]?[0-9])):((?:[0-5][0-9]))(?::((?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)))(?![0-9])))(\s*)(?P<hostname>(\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)))(\s*)(?:%{SPACE})?%{BOSSJONES_UNIFI_PROCESS_NAME}(?:%{SPACE})?(?:%{BOSSJONES_UNIFI_SECURITYGATEWAY_FIREWALL_LOGS})(?:%{BOSSJONES_UNIFI_SECURITYGATEWAY_FIREWALL_LOGS})?(?:%{SPACE})?(?:%{BOSSJONES_UNIFI_SECURITYGATEWAY_FIREWALL_IPTABLES_ETHERNET}|%{BOSSJONES_IPTABLES_IP_START})? (?:%{BOSSJONES_IPTABLES_IP_START})?
```

```
^(?P<month>(\b(?:[Jj]an(?:uary|uar)?|[Ff]eb(?:ruary|ruar)?|[Mm](?:a|ä)?r(?:ch|z)?|[Aa]pr(?:il)?|[Mm]a(?:y|i)?|[Jj]un(?:e|i)?|[Jj]ul(?:y)?|[Aa]ug(?:ust)?|[Ss]ep(?:tember)?|[Oo](?:c|k)?t(?:ober)?|[Nn]ov(?:ember)?|[Dd]e(?:c|z)(?:ember)?)\b))(\s*)(?P<daynum>(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])) (?P<time>((?!<[0-9])((?:2[0123]|[01]?[0-9])):((?:[0-5][0-9]))(?::((?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)))(?![0-9])))(\s*)(?P<hostname>(\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)))(\s*)(?:(\s*))?((?P<process_name>\b\w+\b):)(?:(\s*))?(?:(\[(?P<firewall_interface>\b\w+\b)-(?P<firewall_rule_index>\b\w+\b)-(?P<firewall_rule_action>\b\w+\b)\]))(?:(\[(?P<firewall_interface>\b\w+\b)-(?P<firewall_rule_index>\b\w+\b)-(?P<firewall_rule_action>\b\w+\b)\]))?(?:(\s*))?(?:(IN=(?P<iptables_input_device>.*?) OUT=(?P<iptables_output_device>.*?)?(?: MAC=(?P<mac>(?:(?P<destination_mac>(?:((?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}))|((?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}))|((?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})))):(?P<source_mac>(?:((?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}))|((?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}))|((?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})))):(?P<iptables_ether_type>(?:[A-Fa-f0-9]{2}):(?:[A-Fa-f0-9]{2}))?((?::[A-Fa-f0-9]{2})*)|(?P<destination_mac>(?:((?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}))|((?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}))|((?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}))))((?::[A-Fa-f0-9]{2})*):(?P<iptables_ether_type>(?:[A-Fa-f0-9]{2}):(?:[A-Fa-f0-9]{2}))?)))?)|(SRC=(?P<firewall_source_ip>(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])) DST=(?P<firewall_destination_ip>(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])) LEN=(?P<firewall_packet_length>[0-9]+) TOS=0x(?P<firewall_tos>(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))) PREC=0x(?P<firewall_precidence_field>(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))) TTL=(?P<firewall_ttl>[0-9]+) ID=(?P<firewall_id>[0-9]+)(?:(\s*))?(?:(?P<firewall_dont_fragment>\b\w+\b))?(?:(\s*))?PROTO=(?P<firewall_nf_protocol>\b\w+\b) SPT=(?P<firewall_spt>(?:[+-]?(?:[0-9]+))) DPT=(?P<firewall_dtp>(?:[+-]?(?:[0-9]+))) (?P<firewall_tcp_opts>.*)))? (?:(SRC=(?P<firewall_source_ip>(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])) DST=(?P<firewall_destination_ip>(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])) LEN=(?P<firewall_packet_length>[0-9]+) TOS=0x(?P<firewall_tos>(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))) PREC=0x(?P<firewall_precidence_field>(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))) TTL=(?P<firewall_ttl>[0-9]+) ID=(?P<firewall_id>[0-9]+)(?:(\s*))?(?:(?P<firewall_dont_fragment>\b\w+\b))?(?:(\s*))?PROTO=(?P<firewall_nf_protocol>\b\w+\b) SPT=(?P<firewall_spt>(?:[+-]?(?:[0-9]+))) DPT=(?P<firewall_dtp>(?:[+-]?(?:[0-9]+))) (?P<firewall_tcp_opts>.*)))?
```

## IDS BLOCK

`# EG. Apr 17 21:10:16 UniFiSecurityGateway3P kernel: ALIEN BLOCK: IN=eth0 OUT=eth1 MAC=ff:ff:f2:fe:f0:fc:00:0f:29:08:ff:f2:08:00 SRC=46.246.123.145 DST=192.168.1.24 LEN=29 TOS=0x00 PREC=0x00 TTL=49 ID=4452 DF PROTO=UDP SPT=8888 DPT=60156 LEN=9`

```
(?:(\s*))?((?P<process_name>\b\w+\b):)(?:(\s*))?(?:(\[(?P<firewall_interface>\b\w+\b)-(?P<firewall_rule_index>\b\w+\b)-(?P<firewall_rule_action>\b\w+\b)\]))?((?P<firewall_ids_block_type>\b\w+\b) BLOCK:\s+)(?:(\[(?P<firewall_interface>\b\w+\b)-(?P<firewall_rule_index>\b\w+\b)-(?P<firewall_rule_action>\b\w+\b)\]))?(?:(\s*))?(?:(IN=(?P<iptables_input_device>.*?) OUT=(?P<iptables_output_device>.*?)?(?: MAC=(?P<mac>(?:(?P<destination_mac>(?:((?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}))|((?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}))|((?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})))):(?P<source_mac>(?:((?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}))|((?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}))|((?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})))):(?P<iptables_ether_type>(?:[A-Fa-f0-9]{2}):(?:[A-Fa-f0-9]{2}))?((?::[A-Fa-f0-9]{2})*)|(?P<destination_mac>(?:((?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}))|((?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}))|((?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}))))((?::[A-Fa-f0-9]{2})*):(?P<iptables_ether_type>(?:[A-Fa-f0-9]{2}):(?:[A-Fa-f0-9]{2}))?)))?)|(SRC=(?P<firewall_source_ip>(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])) DST=(?P<firewall_destination_ip>(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])) LEN=(?P<firewall_packet_length>[0-9]+) TOS=0x(?P<firewall_tos>(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))) PREC=0x(?P<firewall_precidence_field>(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))) TTL=(?P<firewall_ttl>[0-9]+) ID=(?P<firewall_id>[0-9]+)(?:(\s*))?(?:(?P<firewall_dont_fragment>\b\w+\b))?(?:(\s*))?PROTO=(?P<firewall_nf_protocol>\b\w+\b) SPT=(?P<firewall_spt>(?:[+-]?(?:[0-9]+))) DPT=(?P<firewall_dtp>(?:[+-]?(?:[0-9]+))) (?P<firewall_tcp_opts>.*)))? (?:(SRC=(?P<firewall_source_ip>(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])) DST=(?P<firewall_destination_ip>(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])) LEN=(?P<firewall_packet_length>[0-9]+) TOS=0x(?P<firewall_tos>(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))) PREC=0x(?P<firewall_precidence_field>(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))) TTL=(?P<firewall_ttl>[0-9]+) ID=(?P<firewall_id>[0-9]+)(?:(\s*))?(?:(?P<firewall_dont_fragment>\b\w+\b))?(?:(\s*))?PROTO=(?P<firewall_nf_protocol>\b\w+\b) SPT=(?P<firewall_spt>(?:[+-]?(?:[0-9]+))) DPT=(?P<firewall_dtp>(?:[+-]?(?:[0-9]+))) (?P<firewall_tcp_opts>.*)))?
```

## IN= then SRC= block

```
# IN= then SRC=
# EG. kernel: [LAN_LOCAL-default-A]IN=eth1 OUT= MAC=ff:ff:f2:fe:f0:fc:00:0f:29:08:ff:f2:08:00 SRC=192.168.1.172 DST=192.168.1.1 LEN=119 TOS=0x00 PREC=0x00 TTL=63 ID=21542 DF PROTO=UDP SPT=5432 DPT=53 LEN=99
```

```
(?:(\s*))?((?P<process_name>\b\w+\b):)(?:(\s*))?(?:(\[%{WORD:firewall_interface}-%{WORD:firewall_rule_index}-%{WORD:firewall_rule_action}\]))?(?:(\[%{WORD:firewall_interface}-%{WORD:firewall_rule_index}-%{WORD:firewall_rule_action}\]))?(?:(\s*))?(IN=%{DATA:iptables_input_device} OUT=%{DATA:iptables_output_device}?(?: MAC=(?P<mac>(?:%{MAC:destination_mac}:%{MAC:source_mac}:%{ETHTYPE:iptables_ether_type}?((?::[A-Fa-f0-9]{2})*)|%{MAC:destination_mac}((?::[A-Fa-f0-9]{2})*):%{ETHTYPE:iptables_ether_type}?)))?) (?:(SRC=%{IPV4:firewall_source_ip} DST=%{IPV4:firewall_destination_ip} LEN=%{UNSIGNED_INT:firewall_packet_length} TOS=0x%{BASE16NUM:firewall_tos} PREC=0x%{BASE16NUM:firewall_precidence_field} TTL=%{UNSIGNED_INT:firewall_ttl} ID=%{UNSIGNED_INT:firewall_id}(?:(\s*))?(?:%{WORD:firewall_dont_fragment})?(?:(\s*))?PROTO=%{WORD:firewall_nf_protocol} SPT=%{INT:firewall_spt} DPT=%{INT:firewall_dtp} %{GREEDYDATA:firewall_tcp_opts}))?
```


## syslog date time and hostname


```
# eg

Apr  7 18:56:11 ubnt kernel: [LAN_LOCAL-default-A]IN=eth0 OUT= MAC=74:ac:b9:1a:a8:09:68:d7:9a:23:fd:f7:08:00 SRC=192.168.1.150 DST=192.168.1.1 LEN=63 TOS=0x00 PREC=0x00 TTL=64 ID=46017 DF PROTO=UDP SPT=60561 DPT=53 LEN=43
```

^(?P<month>(\b(?:[Jj]an(?:uary|uar)?|[Ff]eb(?:ruary|ruar)?|[Mm](?:a|ä)?r(?:ch|z)?|[Aa]pr(?:il)?|[Mm]a(?:y|i)?|[Jj]un(?:e|i)?|[Jj]ul(?:y)?|[Aa]ug(?:ust)?|[Ss]ep(?:tember)?|[Oo](?:c|k)?t(?:ober)?|[Nn]ov(?:ember)?|[Dd]e(?:c|z)(?:ember)?)\b))(\s*)(?P<daynum>(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])) (?P<time>((?!<[0-9])((?:2[0123]|[01]?[0-9])):((?:[0-5][0-9]))(?::((?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)))(?![0-9])))(\s*)(?P<hostname>(\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)))(\s*)


# loki read json logs from fluentd

```

~/dev/bossjones/logstash-patterns-core main*
❯ ./grok-to-regex.py "%{DATE_US}"
(((?:0?[1-9]|1[0-2]))[/-]((?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9]))[/-]((?>\d\d){1,2}))

~/dev/bossjones/logstash-patterns-core main*
❯ ./grok-to-regex.py "%{DATESTAMP}" | pbcopy

~/dev/bossjones/logstash-patterns-core main*
❯ ./grok-to-regex.py "%{TIMESTAMP_ISO8601}" | pbcopy

~/dev/bossjones/logstash-patterns-core main*
❯ ./grok-to-regex.py "%{YEAR}" | pbcopy

~/dev/bossjones/logstash-patterns-core main*
❯ ./grok-to-regex.py "%{MONTHNUM}" | pbcopy

~/dev/bossjones/logstash-patterns-core main*
❯ ./grok-to-regex.py "%{MONTHDAY}" | pbcopy

~/dev/bossjones/logstash-patterns-core main*
❯ ./grok-to-regex.py "%{TIME}" | pbcopy

~/dev/bossjones/logstash-patterns-core main*
❯ ./grok-to-regex.py "%{ISO8601_TIMEZONE}" | pbcopy

~/dev/bossjones/logstash-patterns-core main*
❯ code ../docker-compose-prometheus

~/dev/bossjones/logstash-patterns-core main*
❯

# debug perl issues using this repo:
https://github.com/vjeantet/grok/blob/master/patterns/grok-patterns
```
