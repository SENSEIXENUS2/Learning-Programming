#! /usr/bin/env python
import shodan
import re
from colorama import *
from getpass import getpass
#Using oop again
#initializing Colorama                                     
init(autoreset = True)
class showdan:
      def __init__(self,api_key: str,keyword: str) -> None:
          self.api_key = api_key
          self.keyword = keyword
          #Initializing Shodan api
          self.api = shodan.Shodan(self.api_key)
      #Method for finding ip addresses and displaying them in detailed format
      def search(self) -> str:
          try:
              #Checking for possible ips
              results: dict = self.api.search(self.keyword)
              print(f"{Fore.RED}[+]Results for {self.keyword}") 
              #Results total
              print(f"[+]Results total: {results['total']}")
              counter = 0
              for result in results['matches']:
                  os = result['os']
                  ip_str = result['ip_str']
                  port = result['port']
                  print("-" * 25 + '\n')
                  #Printing out important info e.g ip,hostnames and os
                  if len(result['hostnames']) >= 2:
                     print(f"[+] Hostnames: {result['hostnames'][0]} and {result['hostnames'][1]}")
                  elif len(result['hostnames']) == 1:
                       print(f"[+] Hostnames: {result['hostnames'][0]}")
                  else:
                      print(f"[+]Hostnames: None")

                  print(f"[+]OS : {os}")
                  print(f"[+]Ip_address: {ip_str}")
                  print(f"[+]Port: {port}\n")
                  print("-" * 25+'\n')
          except shodan.APIError as e:
                 print(f"[+]{e}")
                 exit()
#Host lookuup
class showdanHost(showdan):
      def __init__(self,key: str,host: str):
          self.host = host
          self.key = key
          #Initializing the api key
          self.api = shodan.Shodan(self.key)
      def Host(self) -> str:
          try:
             #Host results
             host_results = self.api.host(self.host)
             #printing details
             ip = host_results['ip_str']
             org = host_results['org']
             location = host_results['country_name']
             try:
                vulns = ''.join(('->'+i+"\n\t")for i in host_results['vulns'])
             except KeyError:
                    vulns = 'None'
             ports = host_results['ports']
             print("-" * 25)
             print(f"[+]ip: {ip}")
             print(f"[+]Org: {org}")
             print(f"[+]Vulns: {vulns}")
             #Iterating through port and port details
             for data in host_results['data']:
                 print(f"[+]Port: {data['port']}")
                 print(f"[+]Port Details: {data['data']}")
             print("-" * 25)
          except shodan.APIError as e:
                 print(f"[+]{e}")
#Functiom to return banner
def retbanner() -> str:
    banner = '''
┌─────────────────────┐                                    │▞▀▖▌ ▌▞▀▖▌ ▌▛▀▖▞▀▖▙ ▌│                                    │▚▄ ▙▄▌▌ ▌▌▖▌▌ ▌▙▄▌▌▌▌│
│▖ ▌▌ ▌▌ ▌▙▚▌▌ ▌▌ ▌▌▝▌│
│▝▀ ▘ ▘▝▀ ▘ ▘▀▀ ▘ ▘▘ ▘│
└─────────────────────┘'''
    banner = (f"{Fore.RED}{banner}")
    print(banner)
def main():
    try:
       retbanner()
       apiKey: str = getpass("[+]Enter your Shodan api key:")
       #Checking for key length
       if len(apiKey) < 32:
           print("[+]Invalid key length")
           exit()
       while True:
             option = input("[+]Pick an option('host'|'search'): ")
             match option:
                   case 'host':
                         host = input('[+]Host\'s ip address(ipv4): ')
                         #using regex to determine ip syntax
                         output = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',host)
                         if output == []:
                            print("[+]Wrong ipv4 syntax")
                            exit()
                         #Calling the shodanhost class
                         showdanhost = showdanHost(apiKey,host)
                         showdanhost.Host()
                   case 'search':
                         keyword = input("[+]Enter a keyword: ")
                         #calling showdan class
                         showdanSearch = showdan(apiKey,keyword)
                         showdanSearch.search()
    except KeyboardInterrupt:
           print("\n[+]Exiting...")
           exit()
if __name__ == '__main__':
   main()
          

 
