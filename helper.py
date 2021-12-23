from scapy.all import *
from collections import OrderedDict


def printPanner():
    panner = '''
                                                      
        /+///////+oyyyys+////////+.                     
        -o`````-+++:-..-:+oo:`````.y                     
        :o```.o+.``````````./s-````h                     
        :o.//y:....------.``.-s/```h                     
        :o-ym/...::::::::.```..h.``h                     
        :o`:y.`................o+``h                     
        :o`/h...-------------..oo-`h                     
        :o`-d:................-h-.`h                     
        :o`-:y/-----------...:hy/.`h                     
        :o`..-so:..........:oddhhy+h`                    
        :o`-----/++//:::/++/:/shhhhdy/.`                 
        :o`.......-::///:-.....:ohhhhdhy/.`              
        :o`-----------------------:mhhhhdhs/.`           
        :o`.......................`h./yhhhhdhs:.`        
        :o`----------------------.`h  `-ohhhhhdhs:``     
        :o`-----------------------`h     `/yhhhhhdho:`   
        :o`......................``h        .+hhhhhhdho` 
        `s:-.....................-+/          `:sdhhhhm- 
          .-----------------------`              `+yyy/  
                                                 
   o+     -o-   -o/    +/    -o++++o:+.   :+`oo+++/ +o++oo`-oooo+.    
   NMs   .NM+  .NhM/   Mh    .--Nd--+M/   sM----hN/ mm..--`+M/.-oM/   
   mmNo `ddM/ `mh oN-  Ny       Nh   oNo.yN/  `hd.  dNyyyy +M/.-oM/   
   mh-N+yy:M/ yMdyhMm` My       Nh    .dMh`  -Ns    md   ` +Ms+yM+    
   Nh :Md /M++M/   .Nd`Mmyyyh.  Md     oM:  .MNyyhy NNyyyh-oM:  yM:   
    '''
    print(panner)

def full_duplex(pktList):
    sessions = "Other"
    if 'Ether' in pktList:
        if 'IP' in pktList:
            if 'TCP' in pktList:
                sessions = str(sorted(["TCP", pktList['IP'].src, pktList['TCP'].sport,
                                        pktList['IP'].dst, pktList['TCP'].dport], key=str))
            elif 'UDP' in pktList:
                sessions = str(sorted(["UDP", pktList['IP'].src, pktList['UDP'].sport,
                                        pktList['IP'].dst, pktList['UDP'].dport], key=str))
            elif 'ICMP' in pktList:
                sessions = str(sorted(["ICMP", pktList['IP'].src, pktList['ICMP'].code,
                                        pktList['ICMP'].type, pktList['ICMP'].id], key=str))
            else:
                sessions = str(sorted(
                    ["IP", pktList['IP'].src, pktList['IP'].dst, pktList['IP'].proto], key=str))
        elif 'ARP' in pktList:
            sessions = str(
                sorted(["ARP", pktList['ARP'].psrc, pktList['ARP'].pdst]))
        else:
            pktList.sprintf("Ethernet type=%04xr%", scapy.all.Ether.type)

    return sessions

def getHostsInfo(outputFile):

    hostInfo = [
        'Pkt',
        'Time',
        'SrcIP',
        'SrcPort',
        'DstIP',
        'DstPort',
        'Proto',
        'Size',
        'Method',
        'File',
        'Version'
    ]

    hostsInfo = list()
    
    with open(outputFile, 'r') as reader:
        info = reader.read()
        reader.close()

    #Prepare Hosts info
    temp = info.split('\n')
    tempList = list()
    for x in temp:
        if x:
            tempList.append(x.strip().split())

    for host in tempList:
        hostsInfo.append(OrderedDict(zip(hostInfo, host)))

    return hostsInfo

def isMalicious(fileName, checkResult):
    for index in range(len(checkResult)):
        for file, isMalicious in checkResult[index].items():
            if fileName in file:
                return isMalicious
    