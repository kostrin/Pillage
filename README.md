# Pillage
Pillage is a multithreaded enumeration python script I created for the enumeration phase of penetration tests.

# How it works
When Pillage.py is invoked, the script will run an Nmap scan of the host. It will then save and analyze the nmap scan. If an open port is found with a matching module, it will asynchronously launch a new thread with the appropriate enumeration module to analyze that port for potential vulnerabilities. This is an exhaustive enumeration designed to take awhile and give you results as they are found. Each module was also designed to be able to run independently if you have a specific test that you desire to be run.

Note: This script calls many pentesting programs from the command-line and runs them asynchronously. For the program to work successfully, the applications must be installed separately. I typically run this script from Kali-Linux in a VM because these programs come natively with Kali.

# Bombard
Bombard is a single file pillage with most of the functionality of Pillage. However, the script omits the port scan to speed up scan time. This allows the attacker to customize what services they would like to test.

# Usage
python Pillage.py hosts.txt
python Bombard.py hosts.txt
