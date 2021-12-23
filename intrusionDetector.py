from helper import *
from scapy.all import *

from binascii import hexlify

class IntrusionDetector():

    def __init__(self):
        pass
        
    def loadRules(self):
        rulesDB = 'SignatureDB.rules'
        tcpRules = list()
        udpRules = list()
        with open(rulesDB, 'r') as reader:
            for r in reader:
                rule = r.strip().split(':')
                if 'TCP' in rule:
                    tcpRules.append(rule)
                elif 'UDP' in rule:
                    udpRules.append(rule)
                else:
                    print('Protocol unsupported at the time being')
        return tcpRules, udpRules

    def sortSessions(self, sessions):

        proto = [
            'TCP',
            'UDP',
            'ICMP',
            'IP',
            'ARP'
        ]

        sessionsList = {x: [] for x in proto}

        for session, packets in sessions.items():
            if 'TCP' in session:
                sessionsList['TCP'].append({session: packets})
            elif 'UDP' in session:
                sessionsList['UDP'].append({session: packets})
            elif 'ICMP' in session:
                sessionsList['ICMP'].append({session: packets})
            elif 'IP' in session:
                sessionsList['IP'].append({session: packets})
            elif 'ARP' in session:
                sessionsList['ARP'].append({session: packets})
            else:
                print('undeified')
        return sessionsList
        
    def classifier(self, hexPayload, rules):
        for rule in rules:
                if rule[1].replace(' ', '') in hexPayload:
                    return rule[2]
        return None

    def parseTCP(self, tcpSessions, tcpRules):
        host = [
            'SrcIP',
            'SrcPort',
            'DstIP',
            'DstPort',
            'Proto',
            'Msg'
        ]

        hostsInfo = []
        
        for session in tcpSessions:
            for stream in session:
                for packet in session[stream]:
                    tcpAttacks = {x: None for x in host}
                    if 'Raw' in packet:
                        #Converting the bytes into hexdecimal
                        hex_payload = hexlify(packet['Raw'].load).decode("utf-8")
                        #send the hex value and rules to the classifier to get the result
                        match = self.classifier(hex_payload, tcpRules)
                        if match:
                            tcpAttacks['SrcIP'] = packet['IP'].src
                            tcpAttacks['SrcPort'] = packet['IP'].sport
                            tcpAttacks['DstIP'] = packet['IP'].dst
                            tcpAttacks['DstPort'] = packet['IP'].dport
                            tcpAttacks['Proto'] = packet['IP'].proto
                            tcpAttacks['Msg'] = match
                            hostsInfo.append(tcpAttacks)
        return hostsInfo

    def parseUDP(slef, udpSessions, udpRules):
        host = [
            'SrcIP',
            'SrcPort',
                'DstIP',
                'DstPort',
                'Proto',
                'Msg'
        ]

        hostsInfo = []

        for session in udpSessions:
                for stream in session: 
                    for packet in session[stream]:
                        udpAttacks = {x: None for x in host}
                        #if 'payload' in packet:
                        hex_payload = hexlify(
                            bytes(packet.payload)).decode("utf-8")
                        match = slef.classifier(hex_payload, udpRules)
                        if match:
                            udpAttacks['SrcIP'] = packet['IP'].src
                            udpAttacks['SrcPort'] = packet['IP'].sport
                            udpAttacks['DstIP'] = packet['IP'].dst
                            udpAttacks['DstPort'] = packet['IP'].dport
                            udpAttacks['Proto'] = packet['IP'].proto
                            udpAttacks['Msg'] = match
                            hostsInfo.append(udpAttacks)
        return hostsInfo

    def detectAttacks(self, fileName):
        #load pcap file
        pcap = rdpcap(fileName)
        #prepare sessions list for both TCP and UDP
        sessions = pcap.sessions(full_duplex) #Scapy module
        sessionsList = self.sortSessions(sessions) #Tool module
        #load TCP and UDP rules
        tcpRules, udpRules = self.loadRules()
        
        for proto, psessions in sessionsList.items():
            if psessions:
                if proto == 'TCP':
                    print('[*] Detecting if TCP sessions has malicious traffic...')
                    tcpAttacks = self.parseTCP(psessions, tcpRules)    
                elif proto == 'UDP':
                    print('[*] Detecting if UDP sessions has malicious traffic...')
                    udpAttacks = self.parseUDP(psessions, udpRules)
                else:
                    continue

        return tcpAttacks, udpAttacks
