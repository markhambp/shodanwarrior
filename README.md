# shodanwarrior  
The tool utilises the Shodan API to pull back various site information including the following:  

	1.HTTP Banner  
	2.Ports  
	3.Country  
	4.Domain  
	6.Last Updated  
	7.Host Coordinates  
	8.CVE's (BETA Phase)  
	9.City  
	10.Autonomous Number  
	11.IP Address  
	12.Operating System  
	13.Organisation  

Shodan GUI: https://www.shodan.io/  

Troubleshooting - if experiencing the below error when trying to run the script try the following in terminal:  


Traceback (most recent call last):  
File "shodanwarrior.py", line 2, in <module>  
import shodan  
ImportError: no module named shodan  


Solution:  

	1. pip install shodan  
	2. pip install blessings  
	2. ./shodanwarrior.py or python shodanwarrior.py  
