#!/usr/bin/python
import argparse, time, sys, os
import subprocess, multiprocessing

class Bombard(object):

    def __init__(self):
        self.banner()
        self.parseArgs()
        self.paramStrings=['1.3.6.1.2.1.25.1.6.0', '1.3.6.1.2.1.25.4.2.1.2', '1.3.6.1.2.1.25.4.2.1.4', '1.3.6.1.2.1.25.2.3.1.4', '1.3.6.1.2.1.25.6.3.1.2', '1.3.6.1.4.1.77.1.2.25', '1.3.6.1.2.1.6.13.1.3']
        self.communityList="community.txt"
        self.userList='userList.txt'
        self.passList='passList.txt'
        self.bombardHosts()

    def parseArgs(self):
        parser = argparse.ArgumentParser(prog='Analyzes a group of hosts and enumerates interesting info', add_help=True)
        parser.add_argument('hostfile', help='host range to scan')    
        args = parser.parse_args()
        self.hosts=self.analyzeHostfile(args.hostfile)

    def bombardHosts(self):
        for h in self.hosts:
            protocol=h[2]
            if protocol =="http" or protocol =="https":
                self.addProcess(self.webEnum,[h[0],h[1],h[2]])
            elif protocol == "snmp":
                self.addProcess(self.snmpEnum,[h[0],h[1],h[2]])
            elif protocol == "ssh":
                self.addProcess(self.sshBrute,[h[0],h[1],h[2]])
            elif protocol == "smb":
                self.addProcess(self.smbEnum,[h[0],h[1],h[2]])
            else:
                print "INFO: No module found for {}. Ignored {}:{}".format(protocol,h[0],h[1])


    def addProcess(self, method, arguments):
        p = multiprocessing.Process(target=method, args=(arguments,))   
        p.start()

    def webEnum(self, args):
        print "INFO: Performing nmap http script scan for {}:{}".format(args[0],args[1])
        nmapSCAN = "nmap -sV -Pn -vv -p {} --script='(http* or ssl*) and not (dos or fuzzer or brute)' -oN {}_http.nmap {}".format(args[1],args[0],args[0])
        subprocess.check_output(nmapSCAN, shell=True)

        print "INFO: Performing nikto scan on {}:{}".format(args[0],args[1])
        script="nikto -host {} -port {} -C all >> {}_nikto_{}.txt".format(args[0],args[1],args[0],args[1])
        subprocess.check_output(script, shell=True)

        '''
        print "INFO: Performing dirb scan on {}:{}".format(args[0],args[1])
        dirbList="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
        script="dirb {}://{}:{} {} -S -w >> {}_dirb_{}.txt".format(args[2],args[0],args[1],dirbList,args[0],args[1])
        subprocess.call(script, shell=True)
        '''
        print "INFO: Finished http module for {}:{}".format(args[0],args[1])

    def smbEnum(self, args):
        print "INFO: Performing nmap smb script scan for {}:{}".format(args[0],args[1])
        nmapSCAN = "nmap -sV -Pn -vv -p {} --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1 -oN {}_smb.nmap {}".format(args[1],args[0],args[0])
        subprocess.check_output(nmapSCAN, shell=True)

        print "INFO: Performing ntbscan for {}:{}".format(args[0],args[1])
        nbtSCAN = "nbtscan -r -v -h {} >> {}_smbNbt.txt".format(args[0],args[0])
        subprocess.check_output(nbtSCAN, shell=True)

        print "INFO: Performing enum4Linux scan for {}:{}".format(args[0],args[1])
        try:
            enumSCAN = "enum4linux -a -M -v {} >> {}_smbEnum.txt".format(args[0],args[0])
            subprocess.check_output(enumSCAN, shell=True)
        except:
            print "ERROR: enum4Linux scan FAILED for {}:{}".format(args[0],args[1])
        
        print "INFO: Finished smb module for {}:{}".format(args[0],args[1])

    def snmpEnum(self, args):
        print "INFO: Performing nmap snmp script scan for {}:{}".format(args[0],args[1])
        nmapSCAN = "nmap -sV -Pn -vv -p {} --script=snmp* -oN {}_snmp.nmap {}".format(args[1],args[0],args[0])
        subprocess.check_output(nmapSCAN, shell=True)

        print "INFO: Performing OneSixtyOne snmp scan for {}:{}".format(args[0],args[1])
        oneSixtyOneSCAN="onesixtyone -c {} {} >> {}_161snmp.txt".format(self.communityList, args[0],args[0])
        subprocess.check_output(oneSixtyOneSCAN, shell=True)

        print "INFO: Performing snmpwalk scan for {}:{}".format(args[0],args[1])
        for param in self.paramStrings:
            try:
                snmpWalkSCAN="snmpwalk -c public -v1 {} {} >> {}_snmpwalk.txt;".format(args[0], param, args[0])
                subprocess.check_output(snmpWalkSCAN, shell=True)
            except:
                pass

        print "INFO: Performing snmpcheck scan for {}:{}".format(args[0],args[1])
        try:
            snmpCheckSCAN="snmpcheck -t {} >> {}_snmpcheck.txt;" % (args[0],args[0])
            subprocess.check_output(snmpCheckSCAN, shell=True)
        except:
            pass

        print "INFO: Finished snmp module for {}:{}".format(args[0],args[1])

    def sshBrute(self, args):
        print "INFO: Performing hydra ssh bruteforce against {}:{}".format(args[0],args[1])
        hydraCmd = "hydra -u -t 4 -L {} -P {} -f -s {} -o {}_sshhydra.txt {} ssh".format(self.userList, self.passList, args[1], args[0], args[0])
        try:
            results = subprocess.check_output(hydraCmd, shell=True)
            resultarr = results.split("\n")
            for result in resultarr:
                if "login:" in result:
                    print "[*] Valid ssh credentials found: " + result 
        except:
            print "INFO: No valid ssh credentials found"
       
        print "INFO: Finished ssh module for {}:{}".format(args[0],args[1])

    def analyzeHostfile(self, hostfile):
        try:
            with open(hostfile) as f:
                allHosts=[]
                for line in f:
                    if line[0]=='#':
                        pass
                    else:
                        if len(line.split())==3:
                            # Host  Port Protocol
                            allHosts.append(line.split())
                        else:
                            raise
            return allHosts
        except:
            print "Invalid host file formatting!"
            sys.exit()

    def banner(self):
        print "############################################################"
        print "####                      Bombard                       ####"
        print "####             Asynchronous Host Attack               ####"
        print "############################################################"

if __name__ == "__main__":
    bombard = Bombard()