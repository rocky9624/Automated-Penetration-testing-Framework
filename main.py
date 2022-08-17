# import required modules
from lib_1 import dataProc, ipExtract
from Capture import *
import os

#begin program
proceed = True
resultOutput = ""
IP= input('Please provide the IP Address of the device : ')
while proceed == True:
    #running contents of main.py
    #command = "ifconfig > dump.log"
    #asciFile = "dump.log"

    fMan = dataProc()
    #fMan.runCommand(command)

    #newFMan = ipExtract(fileName=asciFile)
    #iplist = newFMan.processIp()
    
    '''
    If you wish to run the NetDiscover part of the code, uncomment the following lines and please note that it takes a longer execution time. 
    '''

    #Netdiscover
    #NetD=input('Please provide the network interface you wish to capture on')
    #file_NetD = "netdiscover_of_the_device.log" 
    #flag = "-i %s"%(NetD)
    #command = "netdiscover %s > %s" %(flag, fileName)
    #fMan.runCommand(command)
    #fMan.reinitfile(file_NetD)
    #NetD_file=fMan.getContentList()
    #for each in NetD_file:
    #print(each)
    
    
    #NMAP
    fileName = "nmap_of_%s.log" %(IP)
    if len(IP) is not 0:        
        command = "nmap %s > %s" %(IP, fileName)
        fMan.runCommand(command)

     
          
    fileName = "nmap_of_%s.log" %(IP) 
    fMan.reinitfile(fileName)
    file=fMan.getContentList()

    openports=[]
    services=[]
    portinfo=[]
    for each in file:
        if "open" in each:
            tmp = each.split(" open")[0]
            tmp1 =each.split("open ")[1]
            tmp2 =each.split("open ")
            openports.append(tmp)
            services.append(tmp1)
            portinfo.append(tmp2)
    print ('The open ports on the device are: ')
    print (openports)
    print ('The services which are running on these open ports are:')
    print (services)
    print ('The ports which are open and their corresponding services are as follows :')
    print (portinfo)
    
    #Remote ACcess Vulnerability Check
    # list of possible setting
    services = ["ssh", "telnet"]
    toRun = []
    opps = "Y"
    
    while opps == "Y":
        print("Which options would you like to run of :\n")
        print(services)
        print("Choose one eg: ssh")
        tmp = input()
        #resultOutput = "%s\n%s" %(resultOutput, tmp)
        
        if tmp in toRun:
            out = "You have already executed that option! Select another or Proceed to the next option"
            print(out)
            resultOutput = "%s\n%s" %(resultOutput, out)
        elif tmp in services:
            print('Testing for remote access vulnerability....')
            F_name= "ssh_bruteforce_of_%s.log"%(IP)
            user = input('Please enter the user you want to test on : ')
            password_file = input('Please enter the password file you wish to test using in single quotes : ')
            print('NOTE: Please make sure the password file provided is in the same directory')
            Mode = tmp

            flags="-u %s -P %s -h %s -M %s" %(user, password_file, IP, Mode)
            if len(IP) is not 0:
                command = "medusa %s > %s" %(flags, F_name)
                fMan.runCommand(command)
            else:
                print('Please provide a valid IP')

            fMan.reinitfile(F_name)
            RV_file = fMan.getContentList()
            
            Found = False
            for each in RV_file:         
                if "FOUND" in each:
                    Found = True
                    out = "[]ALERT: REMOTE ACCESS VULNERABILITIY DETECTED"
                    print(out)
                    resultOutput = "%s\n%s" %(resultOutput, out)
                    
            if Found == False :
                out = "[]ALERT: Cannot detect any remote access Vulnerability!"             
                print (out)
                resultOutput = "%s\n%s" %(resultOutput, out)          
            #out = "Executing command with flag %s" %(tmp)
            #print(out)
            #resultOutput = "%s\n%s" %(resultOutput, out)
            
            toRun.append(tmp)
        else:
            out = "%s : is not a valid option" %(tmp)
            print(out)
            resultOutput = "%s\n%s" %(resultOutput, out)
        
        # determine whether to exit or proceed
        
        print("Select N to terminate or proceed with option Y\n")
        tmp = input()
        #resultOutput = "%s\n%s" %(resultOutput, tmp)
        
        if tmp == "N":
            opps = "N"
        elif len(services) == len(toRun):
            print("You have explored all options.")
            opps = "N"
        else:
            print("That was an invalid option pick : Y or N next time.")
        
    #Detecting the presence of a web interface
    print('Testing for an Insecure Web Interface...')
    #IP = input('Please provide the IP Address of the device') 
    fMan = dataProc()
    F_name = "whatweb_of_%s.log" %(IP)
    flags = "-v"
    if len(IP) is not 0:
	    command = "whatweb %s %s > %s" %(flags,IP, F_name)
	    fMan.runCommand(command)
    else:
	    print('Please provide a valid IP')

    fMan.reinitfile(F_name)
    whatweb_file = fMan.getContentList()

    Quoted_IP = '"%s"' %(IP)
    #connection_refused="ERROR: Connection refused - connect(2) for %s port 80" %(Quoted_IP)
    WebInterface = True
    Open_Ports = input('Are any of the services http or https on open ports [Y/N] ?')

    #for each in whatweb_file:
    
    for each in whatweb_file:
        if  "Unassigned" in each : 
	        WebInterface = False
	        out = '[]ALERT:This devices does not have a corresponding web interface!'
	        print (out)
	        resultOutput = "%s\n%s" %(resultOutput, out)

	        
    if Open_Ports in ['n' , 'N']:
        WebInterface = False
        out = '[]ALERT:This devices does not have a corresponding web interface!'
        print (out)
        resultOutput = "%s\n%s" %(resultOutput, out)
    #CHECK HTTP status Ok condition
    else :
        WebInterface = True

    #Running Zap-CLi
    if WebInterface == True:
	    print('This device has a web interface!!!')
	    print('Please make sure you have installed zap-cli on your system')
	    print('Running Zap-cli to detect Insecure web interface based Vulerabilities...')

    #command = zap-cli --zap-path /usr/share/zaproxy -p 8099 --api-key 12345 quick-scan --self-contained --spider -r -l Informational -s all http://192.168.137.219/
	    file_zap = "zap_out_of_%s" %(IP)
	    zap_path = input('Please provide the path to the folder "zaproxy" on your system(Default path in Kali :/usr/share/zaproxy)')
	    zap_port = input('Please provide the port on which you wish to run Zap on(Default port 8090) : ')
	    api_key = input('Please provide the API key for the zaproxy : ')
	    scan_level = input('Please provide the level of alerts you wish to see from the scan(Default=High), i.e: High,Medium,Low,Informational(All) : ')
	    scan_type = 'all' 
	    url = "http://%s/" %(IP)
	    flags = "--zap-path %s -p %s --api-key %s quick-scan --self-contained --spider -r -l %s -s %s" %(zap_path, zap_port, api_key, scan_level, scan_type)
	    command = "zap-cli %s %s > %s" %(flags, url, file_zap)
	    fMan.runCommand(command)
	    
	    fMan.reinitfile(file_zap)
	    zap_file = fMan.getContentList()
	    #Check
	    IssuesFound = False
	    for each in zap_file:
	        if "Issues found: 0" in each:
		        IssuesFound = False
		        out = '[]ALERT:Unable to detect any Insecure Web Inerface Vulnerabilties!'
		        print (out)
		        resultOutput = "%s\n%s" %(resultOutput, out)
	        elif "Issues found: 1" in each:
		        IssuesFound = True
		        out ='[]ALERT:INSECURE WEB INTERFACE VULNERABILITY DETECTED!!!'
		        print(out)
		        resultOutput = "%s\n%s" %(resultOutput, out)
	        elif "Issues found: " in each:
		        IssuesFound = True
		        out = '[]ALERT:INSECURE WEB INTERFACE VULNERABILITY DETECTED!!!'
		        print(out)
		        resultOutput = "%s\n%s" %(resultOutput, out)
     
	    
	    if IssuesFound==False :
	        out= '[]ALERT:Unable to detect any Insecure Web Inerface Vulnerabilities!!!'
	        print (out)
	        resultOutput = "%s\n%s" %(resultOutput, out)        
    #manual or automatic capture and testing option
    print("________\nNew stage\n_________")
    print("Network Capturing\nDo you wish to execute this stage Manually or Automatically:\nPick A for auto or M for Manual__")
    tmp = input()
    opps = ["A", "M"]
    
    while tmp not in opps:
        print("please select a valid option:")
        print(opps)
        tmp = input()
        
    if tmp == "A":
        device_ip = input('[?] Provide Device IPAddress : ')
        while True:
            print('[1] Booting Device\n[2] Mobile Application Interaction\n[3] Firmware mode\n[4] Offline mode')
            while True:
                choice = input('[?] Enter Your Choice : ')
                if choice not in ['1', '2', '3', '4']: print('[-] Invalid Selection, Please Select Again!')
                else: break
            if choice == '1': capture_device_boot(device_ip)
            elif choice == '2':
                a = ARP_Spoofing(device_ip)
                a.capture_mobile_app_communication()
            elif choice == '3': capture_firmware()
            elif choice == '4': capture_offline(device_ip)
            check = input('\n[?] Do You Want to Continue [Y/N] : ')
            if check in ['y', 'Y']: continue
            else: break
        print('[!] Exit!!')
        
    #Check for captured firmware files
        Check = input('[?] Have the firmware files been captured [Y/N]')
        
        if Check in ['y' , 'Y']:
            fMan = dataProc()
            #IP = input('Please provide the IP Address of the device')
            Firm_pcap = input('please input the name of the pcap file captured during the firmware update along with the .pcap extention in double quotes : ')
            f ="fields"
            e = "http.request.full_uri"
            sort_uniq = "| sort |uniq"
            URL_list = "uri_list_of_%s.log"%(IP)
            tshark_flags = "-r %s -T %s -e %s %s" %(Firm_pcap, f, e, sort_uniq)
            if len(IP) is not 0:
                command = "tshark %s > %s" %(tshark_flags, URL_list)
                fMan.runCommand(command)

            fMan = dataProc()
            fMan.reinitfile(URL_list)
            URL_file=fMan.getContentList()
            
            hasBin = False
            for each in URL_file:
                if ".bin" in each:
                    hasBin = True
                    print('Found the firmware .bin file!')
                    bin_file = input('Please provide a file name for the bin file that is being extracted with a .bin extention at the end : ')
                    flags = "-O %s" %(bin_file)
                    print('Download in progress....')
                    command = "wget %s %s" %(flags, each)
                    fMan.runCommand(command)
                    print ('The firmware .bin file has now been downloaded and stored in the same directory!') 
                    #Extraction using binwalk
                    command = "binwalk -D='.*' %s" %(bin_file)
                    fMan.runCommand(command)
                    #Extracted Firmware file
                    Extracted_firm = input('Please input the name of the new extracted folder that has been extracted using binwalk : ')
                    print ('DEFAULT: _"bin_file".name.extracted')
                    #Running firmwalker
                    Firmwalker_file = input('Please input the name of the txt file where you wish to store the results of your firmwalker scan : ')
                    flags = "../%s ../%s" %(Extracted_firm, Firmwalker_file)
                    command = "./firmwalker.sh %s" %(flags)
                    fMan.runCommand(command)
                    out = '[]ALERT:Since the firmware files can be captured and extracted, "INSECURE FIRMWARE VULNERABILTY DETECTED"'
                    print(out)
                    resultOutput = "%s\n%s" %(resultOutput, out)

            if hasBin == False:
                out = '[]ALERT:Unable to find the firmware .bin file.Therefore, unable to detect any insecure firmware vulnerability!'
                print (out)
                resultOutput = "%s\n%s" %(resultOutput, out)
        else:        
           #Check for downloaded firmware files
            Check1 = input('[?] Did you get the firmware files from the manufacturers website [Y/N]')
            if Check1 in [ 'y' , 'Y' ]:
                bin_file = input('Please provide the file name of the .bin file downloaded ftom the manufacturers website : ')
                command = "binwalk -D='.*' %s" %(bin_file)
                fMan.runCommand(command)
                #Extracted Firmware file
                Extracted_firm = input('Please input the name of the new extracted folder that has been extracted using binwalk (DEFAULT: _"bin_file".name.extracted) : ')
                #Running firmwalker
                print('Please make sure the firmwalker files are in the same directory as the script which is running and that the fimware file system and the firmwalker-master folder(DEFAULT NAME: firmwalker) are in the same directory')
                Firmwalker_file = input('Please input the name of the txt file where you wish to store the results of your firmwalker scan : ') 
                flags = "../%s/ ../%s" %(Extracted_firm, Firmwalker_file)
                command = "./firmwalker.sh %s" %(flags)
                fMan.runCommand(command)
                out= 'Please check the firmwalker results file to detect vulnerabilties in the firmware. Unfortunately, this cannot be done through automation as it differs in each case!'
                print (out)
                resultOutput = "%s\n%s" %(resultOutput, out)
            
            else:
                out = '[]ALERT:The firmware files could neither be downloaded nor captured. Therefore, unable to detect any insecure firmware vulnerability!'
                print (out)
                resultOutput = "%s\n%s" %(resultOutput, out)
                    
        #Checking for Lack of Transport encryption 
        print('Testing for lack of transport encryption vulnerabiltity...')
        Firm_pcap = input('please input the name of the pcap file captured along with the .pcap extention in double quotes : ')
        f ="fields"
        e = "http.request.full_uri"
        sort_uniq = "| sort |uniq"
        http_list = "http_list_of_%s.log"%(IP)
        tshark_flags = "-r %s -T %s -e %s %s" %(Firm_pcap, f, e, sort_uniq)
        if len(IP) is not 0:
            command = "tshark %s > %s" %(tshark_flags, http_list)
            fMan.runCommand(command)

        fMan.reinitfile(http_list)
        http_file=fMan.getContentList()
        http = False 
        for each in http_file:
            if "http:" in each and "cloud" in each:
                http = True
                print ('Found the http link to the cloud interface...')
                print (each)
                out = '[]ALERT:The cloud interface uses http, therefore "LACK OF TRANSPORT ENCRYPTION VULNERABILITY DETECTED!!'
                print (out)
                resultOutput = "%s\n%s" %(resultOutput, out)

        if http == False:
            out = '[]ALERT:Unable to detect any Lack of transport Encryption'
            print(out)
            resultOutput = "%s\n%s" %(resultOutput, out)            
            
        #Insecure Network Services Check
        print('Testing for Insecure Network Service...')
        fMan = dataProc()
        #IP = input('Please provide the IP Address of the device')
        check=input('Do you wish to read the pcap files to detect network based vulnerabilties[Y/N]?')
        #Extracts the relevant fields required to analyse and detect network based vulnerabilites
        if check in ['y' , 'Y']:
            Read_pcap = input('Please input the name of the pcap file captured along with the .pcap extention in double quotes : ')
            f ="fields"
            e = input ('Please enter the wireshark fields(filter) of the info you wish to extract from the pcap file : ')
            print('NOTE: if you wish to extract more than one filed add an "-e" after each field. Eg: http -e tcp -e ip.addr etc')
            sort_uniq = "| sort |uniq"
            Info_list="Info_list_of_%s" %(IP)
            tshark_flags = "-r %s -T %s -e %s %s" %(Read_pcap, f, e, sort_uniq)
            if len(IP) is not 0:
                command = "tshark %s > %s" %(tshark_flags, Info_list)
                fMan.runCommand(command)


            fMan = dataProc()
            fMan.reinitfile(Info_list)
            Info_file=fMan.getContentList()

            for each in Info_file:
                print (each)
       
        elif check in ['n', 'N']:
        #Using nmap scripts (NSE to detect) network based vulnerabilties.
            print('Testing the Network...')
            file_Nmap="Network_Nmap_of_%s.log" %(IP)
            print('NOTE: Please make sure that the scripts being used are downloaded and installed in the directory /Nmap/Scripts in your system')
            scripts=input('Please input the name of scripts you wish to use for the detection, separated by a comma in between them : ')
            flags = "--script=%s" %(scripts)
            if len(IP) is not 0:
                command = "nmap %s %s >%s" %(flags, IP, file_Nmap)
                fMan.runCommand(command)

            fMan.reinitfile(file_Nmap)
            Nmap_file = fMan.getContentList()
            Check = False
            for each in Nmap_file:
                if "CVE" in Nmap_file or "VULNERABLE" in each:
                    Check = True
                    out = "[]ALERT:INSECURE NETWORK SERVICES VULNERABILITY DETECTED!!"
                    print(out)
                    resultOutput = "%s\n%s" %(resultOutput, out)
                    
            if Check == False :
                out = "[]ALERT:Unable to detect any Insecure Network Services!!"
                print(out)
                resultOutput = "%s\n%s" %(resultOutput, out)
        #print ("Executing in Auto")
    elif tmp == "M":
        #print("Executing in Manual")
        #Detecting Insecure Firmware Vulnerability
        print('Detecting Insecure firmware Vulnerability...')
        Check = input('[?] Have the firmware files been captured [Y/N]')
        
        if Check in ['y' , 'Y']:
            fMan = dataProc()
            #IP = input('Please provide the IP Address of the device')
            Firm_pcap = input('please input the name of the pcap file captured during the firmware update along with the .pcap extention in double quotes : ')
            f ="fields"
            e = "http.request.full_uri"
            sort_uniq = "| sort |uniq"
            URL_list = "uri_list_of_%s.log"%(IP)
            tshark_flags = "-r %s -T %s -e %s %s" %(Firm_pcap, f, e, sort_uniq)
            if len(IP) is not 0:
                command = "tshark %s > %s" %(tshark_flags, URL_list)
                fMan.runCommand(command)

            fMan = dataProc()
            fMan.reinitfile(URL_list)
            URL_file=fMan.getContentList()
            
            hasBin = False
            for each in URL_file:
                if ".bin" in each:
                    hasBin = True
                    print('Found the firmware .bin file!')
                    bin_file = input('Please provide a file name for the bin file that is being extracted with a .bin extention at the end : ')
                    flags = "-O %s" %(bin_file)
                    print('Download in progress....')
                    command = "wget %s %s" %(flags, each)
                    fMan.runCommand(command)
                    print ('The firmware .bin file has now been downloaded and stored in the same directory!') 
                    #Extraction using binwalk
                    command = "binwalk -D='.*' %s" %(bin_file)
                    fMan.runCommand(command)
                    #Extracted Firmware file
                    Extracted_firm = input('Please input the name of the new extracted folder that has been extracted using binwalk : ')
                    print ('DEFAULT: _"bin_file".name.extracted')
                    #Running firmwalker
                    Firmwalker_file = input('Please input the name of the txt file where you wish to store the results of your firmwalker scan : ')
                    flags = "../%s ../%s" %(Extracted_firm, Firmwalker_file)
                    command = "./firmwalker.sh %s" %(flags)
                    fMan.runCommand(command)
                    out = '[]ALERT:Since the firmware files can be captured and extracted, "INSECURE FIRMWARE VULNERABILTY DETECTED"'
                    print(out)
                    resultOutput = "%s\n%s" %(resultOutput, out)

            if hasBin == False:
                out = '[]ALERT:Unable to find the firmware .bin file.Therefore, unable to detect any insecure firmware vulnerability!'
                print (out)
                resultOutput = "%s\n%s" %(resultOutput, out)
        else:        
            Check1 = input('[?] Did you get the firmware files from the manufacturers website [Y/N]')
            if Check1 in [ 'y' , 'Y' ]:
                bin_file = input('Please provide the file name of the .bin file downloaded ftom the manufacturers website : ')
                command = "binwalk -D='.*' %s" %(bin_file)
                fMan.runCommand(command)
                #Extracted Firmware file
                Extracted_firm = input('Please input the name of the new extracted folder that has been extracted using binwalk (DEFAULT: _"bin_file".name.extracted) : ')
                #Running firmwalker
                print('Please make sure the firmwalker files are in the same directory as the script which is running and that the fimware file system and the firmwalker-master folder(DEFAULT NAME: firmwalker) are in the same directory')
                Firmwalker_file = input('Please input the name of the txt file where you wish to store the results of your firmwalker scan : ') 
                flags = "../%s/ ../%s" %(Extracted_firm, Firmwalker_file)
                command = "./firmwalker.sh %s" %(flags)
                fMan.runCommand(command)
                out= 'Please check the firmwalker results file to detect vulnerabilties in the firmware. Unfortunately, this cannot be done through automation as it differs in each case!'
                print (out)
                resultOutput = "%s\n%s" %(resultOutput, out)
            
            else:
                out = '[]ALERT:The firmware files could neither be downloaded nor captured. Therefore, unable to detect any insecure firmware vulnerability!'
                print (out)
                resultOutput = "%s\n%s" %(resultOutput, out)
            
            
            
        #Checking for Lack of Transport encryption 
        print('Testing for lack of transport encryption vulnerabiltity...')
        Firm_pcap = input('please input the name of the pcap file captured along with the .pcap extention in double quotes : ')
        f ="fields"
        e = "http.request.full_uri"
        sort_uniq = "| sort |uniq"
        http_list = "http_list_of_%s.log"%(IP)
        tshark_flags = "-r %s -T %s -e %s %s" %(Firm_pcap, f, e, sort_uniq)
        if len(IP) is not 0:
            command = "tshark %s > %s" %(tshark_flags, http_list)
            fMan.runCommand(command)

        fMan.reinitfile(http_list)
        http_file=fMan.getContentList()
        http = False 
        for each in http_file:
            if "http:" in each and "cloud" in each:
                http = True
                print ('Found the http link to the cloud interface...')
                print (each)
                out = '[]ALERT:The cloud interface uses http, therefore "LACK OF TRANSPORT ENCRYPTION VULNERABILITY DETECTED!!'
                print (out)
                resultOutput = "%s\n%s" %(resultOutput, out)

        if http == False:
            out = '[]ALERT:Unable to detect any Lack of transport Encryption'
            print(out)
            resultOutput = "%s\n%s" %(resultOutput, out)            
            
        #insecure Network Services
        print('Testing for Insecure Network Service...')
        fMan = dataProc()
        #IP = input('Please provide the IP Address of the device')
        check=input('Do you wish to read the pcap files to detect network based vulnerabilties[Y/N]?')
        #Extracts the relevant fields required to analyse and detect network based vulnerabilites
        if check in ['y' , 'Y']:
            Read_pcap = input('Please input the name of the pcap file captured along with the .pcap extention in double quotes : ')
            f ="fields"
            e = input ('Please enter the wireshark fields(filter) of the info you wish to extract from the pcap file : ')
            print('NOTE: if you wish to extract more than one filed add an "-e" after each field. Eg: http -e tcp -e ip.addr etc')
            sort_uniq = "| sort |uniq"
            Info_list="Info_list_of_%s" %(IP)
            tshark_flags = "-r %s -T %s -e %s %s" %(Read_pcap, f, e, sort_uniq)
            if len(IP) is not 0:
                command = "tshark %s > %s" %(tshark_flags, Info_list)
                fMan.runCommand(command)


            fMan = dataProc()
            fMan.reinitfile(Info_list)
            Info_file=fMan.getContentList()

            for each in Info_file:
                print (each)
        #Check the above code
       
        #Using nmap scripts (NSE to detect) network based vulnerabilties.
        print('Testing the Network...')
        file_Nmap="Network_Nmap_of_%s.log" %(IP)
        print('NOTE: Please make sure that the scripts being used are downloaded and installed in the directory /Nmap/Scripts in your system')
        scripts=input('Please input the name of scripts you wish to use for the detection, separated by a comma in between them : ')
        flags = "--script=%s" %(scripts)
        if len(IP) is not 0:
            command = "nmap %s %s >%s" %(flags, IP, file_Nmap)
            fMan.runCommand(command)

        fMan.reinitfile(file_Nmap)
        Nmap_file = fMan.getContentList()
        Check = False
        for each in Nmap_file:
            if "CVE" in Nmap_file or "VULNERABLE" in each:
                Check = True
                out = "[]ALERT:INSECURE NETWORK SERVICES VULNERABILITY DETECTED!!"
                print(out)
                resultOutput = "%s\n%s" %(resultOutput, out)
                
        if Check == False :
            out = "[]ALERT:Unable to detect any Insecure Network Services!!"
            print(out)
            resultOutput = "%s\n%s" %(resultOutput, out)
            

        #COMPLETE
        
        
        
        
    #storing the results to an output
    Results = input('Please enter the file name of the file you wish to store these results in with a .txt extention at the end : ')
    fi = open(Results, "w")
    fi.write(resultOutput)
    fi.close()
        
    #last option loop again or exit. exiting by default
    proceed = False
