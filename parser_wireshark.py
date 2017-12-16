#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import bs4 as bs
import urllib.request
import os

from datetime import datetime as dt

file = open(os.path.expanduser("ws.csv"), "wb")
header= ",Number of Vulnerabilities Found, CVE,CWE,CVSS,NVD Published,WS Published,Status,Attack Window (Days), Total Delays\n"
file.write(bytes(header, encoding="ascii", errors="ignore"))

delay = 0
number_vulnerabilities = 0

def make_soup(file, db):

   if db == "NVD":
      source = open(file).read()

   elif db == "WIRESHARK":
      source = urllib.request.urlopen(file).read() 

   soup = bs.BeautifulSoup(source, 'lxml')
   return soup

def assign_cvss_rating(cvss_score):

    if(float(cvss_score) >= 0.1 and float(cvss_score) <= 3.9):
        cvss_rating = "LOW"
    elif(float(cvss_score) >= 4.0 and float(cvss_score) <= 6.9):
        cvss_rating = "MEDIUM"
    elif(float(cvss_score) >= 7.0 and float(cvss_score) <= 8.9):
        cvss_rating = "HIGH"
    elif(float(cvss_score) >= 9.0 and float(cvss_score) <= 10.0):
        cvss_rating = "CRITICAL"

    return cvss_rating

soup_nvd = make_soup("nvdcve-2.0-2017.xml", "NVD")
entry = soup_nvd.find_all("entry")

for data in entry:
   try:
      product = data.find("vuln:product").text
      cve = data.find("vuln:cve-id").text

      if "wireshark" in product:
          date_nvd = data.find("vuln:published-datetime").text
          cwe_id = data.find("vuln:cwe").get("id")
          cvss_score = data.find("cvss:score").text
          cvss_rating = assign_cvss_rating(cvss_score)
          for reference in data.find_all("vuln:reference"):
            if "bugs.wireshark.org" in reference.text:
              #print(cve, reference.text)

              soup_ws = make_soup(reference.text, "WIRESHARK")
              table = soup_ws.find_all('table')[2]
              print(table)
              td = table.find('td')

              date_nvd = dt.strptime(date_nvd[0:10], "%Y-%m-%d").date()
              date_ws = dt.strptime(td.text[:10], "%Y-%m-%d").date()

              row=""
              if date_ws < date_nvd:
                 status = "DELAY"
                 delta = date_nvd - date_ws
                 delay = delay + 1
                 number_vulnerabilities = number_vulnerabilities + 1
                 print(number_vulnerabilities,cve, cwe_id, cvss_rating, date_nvd, date_ws, "DELAY", delta.days, delay)
                 row = ","+str(number_vulnerabilities)+","+cve+","+cwe_id+","+cvss_rating+","+str(date_nvd)+","+str(date_ws)+","+status+","+str(delta.days)+","+str(delay)+"\n"
                 file.write(bytes(row, encoding="ascii", errors="ignore"))
              else:
                 status = "NO DELAY"
                 number_vulnerabilities=number_vulnerabilities + 1
                 print(number_vulnerabilities,cve, cwe_id, cvss_rating, date_nvd, date_ws, "NO DELAY", delay)
                 row = ","+str(number_vulnerabilities)+","+cve+","+cwe_id+","+cvss_rating+","+str(date_nvd)+","+str(date_ws)+","+status+","+""+","+str(delay)+"\n"
                 file.write(bytes(row, encoding="ascii", errors="ignore"))

   except:
      continue
