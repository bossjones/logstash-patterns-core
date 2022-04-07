#!/usr/bin/env python
# SOURCE: https://gist.githubusercontent.com/elementalvoid/59afc405f2f5726ad1980e8d8178536b/raw/3e2a6a88ef10acc5d95272cea90cd01a6fa7c6d9/grok-to-regex.py
import argparse
import re
from os import walk
from os.path import join
from pygrok import Grok


def get_patterns(patterns_dir):
    patterns = {}
    for (dirpath, _, filenames) in walk(patterns_dir):
        for name in filenames:
            with open(join(dirpath, name)) as f:
                for line in f.readlines():
                    if not line.startswith('#') and not line.strip() == "":
                        k, v = line.split(' ', 1)
                        patterns[k] = v.rstrip('\n')
    return patterns

def dump_regex(expression, patterns_dir):
    pattern = expression
    grok = Grok(pattern, custom_patterns_dir=patterns_dir)
    # print(f"{grok.regex_obj.pattern}")
    print(f"{grok.regex_obj.pattern}")
    
def convert(expression, patterns):
    groks = re.compile('%{[^}]*}')

    failed_matches = set()
    matches_prev_len = 0

    while True:
        matches = groks.findall(expression)
        matches_cur_len = len(matches)
        if matches_cur_len == 0 or matches_cur_len == matches_prev_len:
            break
        for m in matches:
            inner = m.strip('%{}')
            if ':' in inner:
                patt, name = inner.split(':')
                replacement = '(?<{}>{{}})'.format(name)
            else:
                patt = inner
                replacement = '{}'

            if not patt in list(patterns.keys()):
                failed_matches.add(patt)
                continue

            expression = expression.replace(m, replacement.format(patterns[patt]))
        matches_prev_len = matches_cur_len

    print(expression)
    if failed_matches:
        global args
        print('\nWarning! Unable to match the following expressions:')
        print('  {}'.format(', '.join(failed_matches)))
        print('This could be a typo or a missing grok pattern file. Double check your grok patterns directory: {}'.format(
            args.patterns_dir
        ))


if __name__ == '__main__':
    # grok-to-regex.py "%{HOSTPORT}" -d patterns/
    # (SRC=%{IPV4:firewall.source.ip} DST=%{IPV4:firewall.destination.ip} LEN=%{UNSIGNED_INT:firewall.packet_length} TOS=0x%{BASE16NUM:firewall.tos} PREC=0x%{BASE16NUM:firewall.precidence_field} TTL=%{UNSIGNED_INT:firewall.ttl} ID=%{UNSIGNED_INT:firewall.id}(?:(\s*))?(?:%{WORD:firewall.dont_fragment})?(?:(\s*))?PROTO=%{WORD:firewall.nf_protocol} SPT=%{INT:firewall.spt} DPT=%{INT:firewall.dtp} %{GREEDYDATA:firewall.tcp_opts})
    #  ./grok-to-regex.py "%{BOSSJONES_IPTABLES_IP_START}"
    #  ./grok-to-regex.py "%{IPV4}"
    #  ./grok-to-regex.py "%{UNSIGNED_INT}"
    #  ./grok-to-regex.py "%{BASE16NUM}"
    #  ./grok-to-regex.py "%{WORD}"
    #  ./grok-to-regex.py "%{INT}"
    #  ./grok-to-regex.py "%{GREEDYDATA}"
    parser = argparse.ArgumentParser()
    parser.add_argument('expression', metavar='expr', help='A grok expression.')
    parser.add_argument('-d', '--patterns-dir', dest='patterns_dir', default='patterns/legacy',
                        help='Directory to find grok patterns.')
    args = parser.parse_args()
    # patterns = get_patterns(args.patterns_dir)
    dump_regex(args.expression, args.patterns_dir)