import argparse
import dpkt
import socket
from collections import Counter

websites = {}
allqueries = []


def extract_dns_queries(pcapng_file, source):

    source_ip = socket.inet_aton(source)
    dns_queries = []
    global allqueries

    with open(pcapng_file, 'rb') as file:

        pcap = dpkt.pcapng.Reader(file)

        for ts, buf in pcap:

            eth = dpkt.ethernet.Ethernet(buf)

            if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.udp.UDP):

                ip = eth.data
                udp = eth.data.data

                if ip.src == source_ip:

                    if hasattr(udp, 'data') and (udp.sport == 53 or udp.dport == 53):

                        try:
                            dns = dpkt.dns.DNS(udp.data)
                        except:
                            continue
                        for qname in dns.qd:

                            allqueries.append(qname.name)
                            substrings_to_check = ["googleapi", "googlevideo", "update", "security", ".org", "microsoft.com", "twimg.com", "ytimg.com"]

                            if any(substring in qname.name for substring in substrings_to_check):
                                continue
                            else:
                                
                                if qname.name.endswith(".mshome.net"):
                                    qname.name = qname.name[:-len(".mshome.net")]

                                words = qname.name.split('.')

                                com_position = -1
                                gg_position = -1
                                net_position = -1
                                in_position = -1
                                
                                for i, word in enumerate(words):
                                    if word == 'com':
                                        com_position = i
                                    elif word == 'gg':
                                        gg_position = i
                                    elif word == 'net':
                                        net_position = i
                                    elif word == 'in':
                                        in_position = i
                                
                                if com_position != -1:

                                    if com_position >= 2 and (words[com_position - 1] == 'google' or words[com_position - 1] == 'live' or words[com_position - 1] == 'msn') and words[com_position -2] != "www":
                                        dns_queries.append(f"{words[com_position - 2]}.{words[com_position - 1]}.com")

                                    elif com_position >= 1 and words[com_position - 1] != 'gstatic' and words[com_position - 1] != 'google' and words[com_position - 1] != 'ggpht' and words[com_position - 1] != 'brave' and words[com_position - 1] != 'quickheal':
                                        dns_queries.append(f"{words[com_position - 1]}.com")
                                elif in_position !=-1:

                                    if in_position >=2:
                                        dns_queries.append(f"{words[in_position - 2]}.{words[in_position - 1]}.in")

                                    elif in_position >=1:
                                        dns_queries.append(f"{words[in_position - 1]}.in")
                                elif gg_position >= 1:

                                    dns_queries.append(f"{words[gg_position - 1]}.gg")
                                elif net_position >= 1:

                                    dns_queries.append(f"{words[net_position - 1]}.net")
    return dns_queries

def count_website_frequency(dns_queries,num):

    prev_query = None
    tempsites = {}

    for query in dns_queries:

        if query != prev_query:
            if query in tempsites:
                tempsites[query] += 1
            else:
                tempsites[query] = 1
            if query in websites:
                websites[query] += 1
            else:
                websites[query] = 1
            prev_query = query

    print("***Top websites visited by User{}***".format(num))

    tempsites = dict(sorted(tempsites.items(), key=lambda item: item[1], reverse=True))
    k = Counter(tempsites) 
    topsites = k.most_common(3)
    for website in topsites:
        print("website: {}, frequency: {}".format(website[0], website[1]))
    
    print('\n')
    return websites

def main(args):
    
    dns_queries = []
    n = int(args[0])
    range = 2*n
    i = 1
    j = 1
    while(i<range):
        dns_queries = extract_dns_queries(args[i], args[i+1])
        count_website_frequency(dns_queries,j)
        i+=2
        j+=1

    global websites, allqueries
    print("**Top websites visited collectively**\n")

    websites = dict(sorted(websites.items(), key=lambda item: item[1], reverse=True))
    topsites = Counter(websites).most_common(15)
    for website in topsites:
        print("website: {}, frequency: {}".format(website[0],website[1]))
    
    

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="pcap processor")
    parser.add_argument("args", nargs="*", help="no. of pcaps, pcap file names with .pcap, source ip addresses(in hexa notation)")

    args = parser.parse_args().args
    main(args)
