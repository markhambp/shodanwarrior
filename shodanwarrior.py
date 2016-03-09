#!/usr/bin/python
import shodan
import requests
import blessings

t = blessings.Terminal()
width = t.width

#create and intilaise API object so that you can connect to shodan API
api = shodan.Shodan("2EunWh2yw16Z3ohUseDPVcdICIS5yHGa")
#servicesi = api.services()
def menu():
    print t.clear()
    print t.bold_green + """
      _               _                                           _            
     | |             | |                                         (_)           
  ___| |__   ___   __| | __ _ _ __ ________      ____ _ _ __ _ __ _  ___  _ __ 
 / __| '_ \ / _ \ / _` |/ _` | '_ \______\ \ /\ / / _` | '__| '__| |/ _ \| '__|
 \__ \ | | | (_) | (_| | (_| | | | |      \ V  V / (_| | |  | |  | | (_) | |   
 |___/_| |_|\___/ \__,_|\__,_|_| |_|       \_/\_/ \__,_|_|  |_|  |_|\___/|_|"""
    print t.bold_green + "\n ---------------------------------------------------- " + t.bold_red + "BPM 2015 - Release v1.4.2" + t.normal

menu()
#Output scan contents to file
output = ""

#specify target for information gathering in raw_input field with our static variable
print
print (' USAGE EXAMPLE: testsitedomain.com or X.X.X.X')
print
target = raw_input(' Enter Target Domain/IP: ')
print

#the variable dns res == resolve ip in target box and utilise shodan API to pull down information from shodans databases
dnsRes = "https://api.shodan.io/dns/resolve?hostnames=" + target + "&key=" + "2EunWh2yw16Z3ohUseDPVcdICIS5yHGa"

#wrap in a try/except block to catch errors.
try:

    #resolve target domainname making a get request to the shodan dns resolver.
    resolved = requests.get(dnsRes)
    #returned json from the get will hold the target information, which is entered above in the target variable raw_input.
    hostIP = resolved.json()[target]
    #lookup and print targethost information
    host = api.host(hostIP) #history=True #set second parameter to true for a history call banner history for the host.

    print 'Host IP: %s' % host['ip_str']
    output += '\nHost IP: %s' % host['ip_str']
    print 'Domain: %s' % host['data'][0]['domains'][0]
    output += '\nDomain: %s' % host['data'][0]['domains'][0]
    print 'Organisation: %s' % host.get('org', 'n/a')
    output += '\nOrganisation: %s' % host.get('org', 'n/a')
    print 'Operating System: %s' % host.get('os', 'n/a')
    output += '\nOperating System: %s' % host.get('os', 'n/a')
    #print 'ASN No: %s' % host['asn']
    print 'ISP: %s' % host['isp']
    output += '\nISP: %s' % host['isp']
    print 60* '-'
    print 'Country: %s' % str(host["data"][0]["location"]["country_name"])
    output += '\nCountry: %s' % str(host["data"][0]["location"]["country_name"])
    print 'Country Code: %s' % host["data"][0]["location"]["country_code3"]
    output += '\nCountry Code: %s' % host["data"][0]["location"]["country_code3"]
    print 'City: %s' % host['data'][0]['location']['city']
    output += '\nCity: %s' % host['data'][0]['location']['city']
    print 
    print 'Last Updated: %s' % host["last_update"]
    output += '\nLast Updated: %s' % host["last_update"]
    print 'Coordinates: %s' % str(host["data"][0]["location"]["latitude"]) + "," + str(host["data"][0]["location"]["longitude"])
    output += '\nCoordinates: %s' % str(host["data"][0]["location"]["latitude"]) + "," + str(host["data"][0]["location"]["longitude"])
    print 'Open Ports: %s' % host['ports']
    output += '\nOpen Ports: %s' % host['ports']
    print 60* '-'

    #print banners 
    print "Banner: %s" % host["data"][0]["data"]
    output += "\nBanner: %s" % host["data"][0]["data"]
    #pull the vulns element from host data array and return common vulns and exposures (CVE) numbers that shodan believes the server is potentially vulnerable too.
    item = host["vulns"][0]
    CVE = item.replace("!","")
    print "Vulnerability: %s" % item
    #use shodan library exploit function to grab information about the vulnerability.
    exploits = api.exploits.search(CVE)
    exploit = exploits["matches"][0]

    if (exploit.get("cve")[0][0:3] == "CVE"):
        print exploit.get("description")
        output += '\n' + exploit.get("description") + '\n'
        print
    #specifiy whethere or not to save file using a raw input
    save_this = raw_input('Save Output [Y]/n: ')
    #if y is entered save file or if nothing is enterered save file as defualt filename.
    if save_this == "y" or save_this == "":
        filename = raw_input('Enter File Name: ')
        if filename == "":
            filename = "Shodan-Output-Default"
    #write filename as an outputfile
        with open(filename,'w') as OUTPUTFILE:
            OUTPUTFILE.write(output)
            OUTPUTFILE.close()

    #print the name of file using the (%s) which will print name entered to save file as.
        print 60* '-'
        print "** Scan content has beed saved to %s **" % filename
        print 60* '-'
    else:
        print "Exiting..."

except Exception as e:
    print 
    print " ***AN ERROR HAS BEEN DETECTED*** - " + str(e)
    print
