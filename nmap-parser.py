# -*- coding: utf-8 -*-
### Dev phase
# -port listing
# -OS listing
# -Script listing
# -Exploits listing

# Execute exploit on open port with parameters

import os
import codecs
import nmap
import argparse
from prettytable import PrettyTable

os.system('cls' if os.name == 'nt' else 'clear')
codecs.register(
    lambda name: codecs.lookup('utf-8') if name == 'cp65001' else None)


class nparser(object):

    def __init__(self):
        self.desc="""
           _ . - = - . _
       . "  \  \   /  /  " .
     ,  \                 /  .
   . \   _,.--~=~"~=~--.._   / .      Nmap Parser v1.0
  ;  _.-"  / \ !   ! / \  "-._  .       - UnkL4b - 
 / ,"     / ,` .---. `, \     ". \\       
/.'   `~  |   /:::::\   |  ~`   '.\\
\`.  `~   |   \:::::/   | ~`  ~ .'/
 \ `.  `~ \ `, `~~~' ,` /   ~`.' /
  .  "-._  \ / !   ! \ /  _.-"  .
   ./    "=~~.._  _..~~=`"    \.
     ,/         ""          \,
       . _/             \_ . 
          " - ./. .\. - "

        """
        print(self.desc)
        parser = argparse.ArgumentParser(self.desc)
        parser.add_argument('-f', '--file', metavar='scan_nmap.xml', help='Specify file from parse')
        parser.add_argument('-o', '--output', metavar='output.txt', help='Set file to output')
        self.args = parser.parse_args()
        if self.args.file is None:
            os.system('cls' if os.name == 'nt' else 'clear')
            parser.print_help()
            exit()
        self.script_list = []
        self.ip_list = []
        self.port_list = {}
        self.product_list = []
        self.nm = nmap.PortScanner()

    def print_script(self):
        print("""\n~~~~~~~~~\n
+------------------+
|  SCRIPT LISTING  |
+------------------+
""")
        for script in self.script_list:
            print("\n--> SCRIPT %s" % (script.upper()))
            table_script = PrettyTable(['IP', 'PORT', 'PROTOCOL', 'RESULT_SCRIPT'])
            for ip in self.ip_list:
                for port in self.port_list:
                    try:
                        if script in self.nm[ip][self.port_list[port]][port]['script']:
                            result_script = self.nm[ip][self.port_list[port]][port]['script'][script]
                            table_script.add_row([ip, port, self.port_list[port], result_script])
                    except KeyError:
                        pass
            print(table_script)

    def print_ports(self):
        print("""
+------------------+
|   PORT LISTING   |
+------------------+
""")
        for port in self.port_list:
            print("\n--> PORT %s" % (port))
            print("--> %s" % (self.port_list[port].upper()))
            table_port = PrettyTable(['MAC', 'IP', 'STATUS_PORT', 'PRODUCT', 'VERSION', 'TYPE', 'CPE'])
            for ip in self.ip_list:
                try:
                    if port in self.nm[ip][self.port_list[port]]:
                        status = self.nm[ip][self.port_list[port]][port]['state']
                        product = self.nm[ip][self.port_list[port]][port]['product']
                        vers = self.nm[ip][self.port_list[port]][port]['version']
                        tp = self.nm[ip][self.port_list[port]][port]['name']
                        cpe = self.nm[ip][self.port_list[port]][port]['cpe']
                        try:
                            macaddr = self.nm[ip]['addresses']['mac']
                        except:
                            macaddr = '---'
                        if product not in self.product_list:
                            self.product_list.append(product)
                        table_port.add_row([macaddr,ip,status,product,vers,tp,cpe])
                except KeyError:
                    pass
            print(table_port)


    def list_port(self, ip):
        try:
            for port in self.nm[ip]['udp']:
                if port not in self.port_list:
                    self.port_list.update({port:'udp'})
                self.list_scripts(self.nm[ip]['udp'][port])
        except KeyError:
            pass
        try:
            for port in self.nm[ip]['tcp']:
                if port not in self.port_list:
                    self.port_list.update({port:'tcp'})
                self.list_scripts(self.nm[ip]['tcp'][port])
        except KeyError:
            pass

    def list_scripts(self, content): 
        if 'script' in content:
            for scrp in content['script']:
                if scrp not in self.script_list:
                    self.script_list.append(scrp)

    def list_ips(self):
        for ips in self.nm.all_hosts():
            self.list_port(ips)
            self.ip_list.append(ips)

    def parse(self):
        with open(self.args.file, 'r') as xml_file:
            xml_content = xml_file.read()
            self.nm.analyse_nmap_xml_scan(xml_content)
            self.list_ips()
            self.print_ports()
            self.print_script()
           
nparser().parse()
