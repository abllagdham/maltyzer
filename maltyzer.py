#!/usr/bin/python

###############################################################################
#
#                       Tool Name: Malicious Packet Analyzer (Maltyzer)
#                       Description: This tool is used to process a pcap file and
#                                       try to idenify malicious traffic and files. 
#                       Author: Amin Bllagdham
#                       Creation date: 1 Nov 2021
#                       Dependiences: Scapy
#                                       (pip install scapy)
################################################################################

#Python builtin Module 
import argparse
import os
import sys

from subprocess import check_call, CalledProcessError
from multiprocessing import Pool
from shutil import rmtree

#Tool-specific modules
import fileProcessor as fp
import intrusionDetector as id
import reporting 

from helper import *

def intrusionDetc(fileName):
    print('[*] Extracting and detecting Malicious traffic from payloads from \'' + fileName + '\' ...')
    #Create IntrusionDetector Object
    intDetct = id.IntrusionDetector()
    tcpAttacks, udpAttacks = intDetct.detectAttacks(fileName)
    
    identifiedAttacks = tcpAttacks + udpAttacks

    #Return identified attacks to be included in the report
    return identifiedAttacks

def fileProc(fileName):
    
    outputFile = 'output.txt'
    #Make dir for extracted files

    extracted = 'Extracted Files'
    cwd = os.getcwd()
    path = os.path.join(cwd, extracted)

    if os.path.isdir(path):
        rmtree(path, ignore_errors=False, onerror=None)
    
    os.mkdir(path)
    
    if not any(os.scandir(path)):
        print('[*] Extracting files from \'' + fileName + '\' ...')
        #Extract using tshark
        ext = 'http,' + extracted
        try:
            output = open(outputFile, "w")
            check_call(('C:\\Program Files\\Wireshark\\tshark.exe', '-r',
                        fileName, '-Y', 'http.request.method == "GET"',
                        '--export-objects', ext), stdout=output)
            output.close()
        except CalledProcessError as e:
            print(e)
            print('[-] Existing...')
            return e
    else:
        print('[+] Files already extracted at: ' + path)

    if not any(os.scandir(path)):
        return None

    #Get list of all extracted files
    filesList = [f for f in os.listdir(
        path) if os.path.isfile(os.path.join(path, f))]

    #Create FileProcessor Object
    fProcessor = fp.FileProcessor()

    #Check files hash value
    print('[*] Computing Hash value for extracted files...')
    filesHash = fProcessor.computeHash(path, filesList)

    print('[*] Detecting if extracted files are malicious...')
    checkResult = fProcessor.checkHash(filesHash)

    hostsInfo = getHostsInfo(outputFile)

    for x in hostsInfo:
        index = x['File'].rfind('/')
        filename = x['File'][index+1:]
        for hash in filesHash:
            if filename in str(hash.keys()):
                x['Hash'] = hash[filename]
        x['isMalicious'] = isMalicious(filename, checkResult)
        
    #Return hashes check to be included in the report
    return hostsInfo


#Program Entery Point
if __name__ == '__main__':

    #Setting up the arguments parser
    parser = argparse.ArgumentParser(prog='Maltyzer', description='Malicious Traffic Analyzer')
    
    #Required arguments
    requiredName = parser.add_argument_group('required arguments')
    requiredName.add_argument('pcap', metavar='<pcap filename>', help='pcap file to be parsed')
    requiredName.add_argument('-o', metavar='<file name>', help='Write output to text <file name> file', required=True)
    
    #Store arguments in variable
    args = parser.parse_args()

    #Getting PCAP filename
    fileName = args.pcap
    if not os.path.isfile(fileName):
        print('"{}" does not exist'.format(fileName))
        sys.exit(-1)

    #Setting output file
    outputFile = args.o
    if not outputFile.endswith('.txt'):
        outputFile += '.txt'

    #Mutliprocessing to call the tool's functions 
    detector = Pool()
    processor = Pool()

    printPanner()
    
    print(
        '[*] Loading \'' + fileName + '\' ...')
    #Execute both functions in parallel
    detectorResult = detector.apply_async(intrusionDetc, (fileName,))
    extractorResult = processor.apply_async(fileProc, (fileName,))

    #Wait for execution to get Identified Attacks returned from the detector
    identifiedAttacks = detectorResult.get()

    #Wait for execution to get Hashes Check returned from the extractor
    filesResult = extractorResult.get()

    print('[+] Malicious Files and Payloads results are ready')
    
    print('[*] Making report...')
    
    #Once results are ready, call reporting tool to prepare the report
    reportWriter = reporting.Reporting(outputFile)
    reportWriter.makeReport(identifiedAttacks, filesResult)

    print('[*] Report ready, opening report...')

    os.startfile(outputFile)

    print('[+] Done.. happy harvesting!')
    sys.exit(0)
