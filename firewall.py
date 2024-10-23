#!/usr/local/bin/python


import argparse
import netfilterqueue
import subprocess

from scapy.all import *

import logging
import logging.config
import colorlog
import sys

"""
default configs for the loggers in the rafece2
"""

# Define the format and log colors
log_format = '%(asctime)s [%(levelname)s] %(name)s [%(funcName)s]: %(message)s'
log_colors = {
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bold_red',
        }

# Create the ColoredFormatter object
console_formatter = colorlog.ColoredFormatter(
        '%(log_color)s' + log_format,
        log_colors = log_colors
        )


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(console_formatter)

logger.addHandler(stdout_handler)

WHITE_LISTED_DOMAINS=open("./white_listed_domains.txt").readlines()

def handle_args():
    #isn dst_port dst_ip
    p = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    p.add_argument("-s", "--seq", type=int, required = True, 
                    help="tcp sequence to drop")
    p.add_argument("-p", "--dport", type=int,
                    help="dst port number")
    p.add_argument("-i", "--dst_ip", type=str,
                    help="dst ip address")
                    

    return(p.parse_args())

def nfque_clean_up(nfque, RULE_NUM, RULE_LEN):
    # Cleanup
    nfque.unbind()
    for i in range(RULE_LEN):
        subprocess.run(['/usr/sbin/iptables', '-D', 'FORWARD', RULE_NUM])
        subprocess.run(['/usr/sbin/iptables', '-D', 'OUTPUT', RULE_NUM])


def main():


    global args
    #args = handle_args()


    # The NFQUEUE to use, just need to be consitent between nfqueue and iptables
    QUE_NUM = 0

    # Setup iptables rules to collect traffic
    RULE_LEN = 0    
    RULE_NUM = '1'
    interceptRule = ['/usr/sbin/iptables', '-t', 'filter', '-I', 'FORWARD', RULE_NUM]
    interceptRule.extend(['--protocol', 'udp'])
    interceptRule.extend(['--dport', "53"])
    interceptRule.extend(['--jump', 'NFQUEUE', '--queue-num', str(QUE_NUM)])
    subprocess.run(interceptRule)
    RULE_LEN += 1

    interceptRule = ['/usr/sbin/iptables', '-t', 'filter', '-I', 'FORWARD', RULE_NUM]
    interceptRule.extend(['--protocol', 'tcp'])
    interceptRule.extend(['--dport', "53"])
    interceptRule.extend(['--jump', 'NFQUEUE', '--queue-num', str(QUE_NUM)])
    subprocess.run(interceptRule)
    RULE_LEN += 1


    interceptRule = ['/usr/sbin/iptables', '-t', 'filter', '-I', 'OUTPUT', RULE_NUM]
    interceptRule.extend(['--protocol', 'udp'])
    interceptRule.extend(['--dport', "53"])
    interceptRule.extend(['--jump', 'NFQUEUE', '--queue-num', str(QUE_NUM)])
    subprocess.run(interceptRule)

    interceptRule = ['/usr/sbin/iptables', '-t', 'filter', '-I', 'OUTPUT', RULE_NUM]
    interceptRule.extend(['--protocol', 'tcp'])
    interceptRule.extend(['--dport', "53"])
    interceptRule.extend(['--jump', 'NFQUEUE', '--queue-num', str(QUE_NUM)])
    subprocess.run(interceptRule)



    nfque = netfilterqueue.NetfilterQueue()
    nfque.bind(QUE_NUM, filter_packet)

    try:
        logger.info("initializing the firewall")
        logger.info(f"white listed domains : {WHITE_LISTED_DOMAINS}")
        nfque.run()
    except KeyboardInterrupt:
        logger.info('User interupt, exiting')
    except Exception as e:
        print(e)
        nfque_clean_up(nfque, RULE_NUM, RULE_LEN)
        exit(1)
    nfque_clean_up(nfque, RULE_NUM, RULE_LEN)
    exit(0)

def contains_illegal_domain(pkt):
    #TODO match by regex, not concrete domain name to prevent redirection abuse
    for qd in pkt[DNS].qd:
        if qd.qname not in WHITE_LISTED_DOMAINS:
            logger.error(f"illegal domain name was tried to be resolved : {qd.qname}")
            logger.error("device info : ")
            device_info = pkg[Ether].src if Ether in pkt else ""
            device_info = f" {pkt[IP].src} --> {pkt[IP].dst}"
            logger.error(device_info)
            return True

    return False


def filter_packet(packet):
    global args, message

    pkt = IP(packet.get_payload())

    if DNS in pkt:
        if contains_illegal_domain(pkt):
            packet.drop()
            logger.debug(f"dropped {pkt}")
            return

    logger.debug(f"accepting {pkt}")
    packet.accept()

if __name__ == "__main__":
    main()
    

