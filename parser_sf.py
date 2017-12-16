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

file = open(os.path.expanduser("securityfocus.csv"), "wb")
header= ",Number of Vulnerabilities Found, CVE,CWE,CVSS,NVD Published,SF Published,Status,Attack Window (Days), Total Delays\n"
file.write(bytes(header, encoding="ascii", errors="ignore"))

cve_source = urllib.request.urlopen("http://cve.mitre.org/data/refs/refmap/source-BID.html").read()
cve_soup = bs.BeautifulSoup(cve_source, 'lxml')
url = 'http://www.securityfocus.com/bid/'
delay = 0
number_vulnerabilities = 0

def assign_month_number(month):

  return {
   'Jan': '01',
   'Feb': '02',
   'Mar': '03',
   'Apr': '04',
   'May': '05',
   'Jun': '06',
   'Jul': '07',
   'Aug': '08',
   'Sep': '09',
   'Oct': '10',
   'Nov': '11',
   'Dec': '12'

    }[month]

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


def make_soup(file, db):
    if db == "NVD":
       source = open(file).read()
                  
    elif db =="SECURITYFOCUS":
       source = urllib.request.urlopen(file).read()
                               
    soup = bs.BeautifulSoup(source, 'lxml')
    return soup

def nvd(cve_sf):
    print("ENTERED FUNCTION WITH", cve_sf)
    #print(cve_exdb)

    soup = make_soup('nvdcve-2.0-2017.xml', "NVD")
    entry = soup.find_all("entry")
    
    #cve_sf = cve_sf.split(" ", 1)[0]
    #print(cve_sf)
    
    for data in entry:
       cve = data.find("vuln:cve-id").text

       if (cve == cve_sf):
          datetime = data.find("vuln:published-datetime").text
          try:
             cvss_score = data.find("cvss:score").text
          except:
              cvss_score = "NOT DEFINED"
          try:
              cwe_id = data.find("vuln:cwe").get("id")
          except:
              cwe_id = "NOT DEFINED"
          #print(cwe_id, cvss_score)
          return datetime, cwe_id, cvss_score 
            
          # if datetime[:7] == "2017-09":
             # print(cve, "----", datetime)
           #   return datetime


table = cve_soup.find_all('table')
table_rows = table[3].find_all('tr')

for tr in table_rows:
    td = tr.find_all('td')
    #row = [i.text for i in td]
    entry = td[1].text
    
    #print(row[:9])
    entry = " ".join(line.strip() for line in entry.split("\n"))
    #print(row)
    if 'CVE-2017' in entry:
     try:
       sf = td[0].text
       sf_bid = sf[4:]
      # sf_bid = "100516"
       soup = make_soup(url+sf_bid, "SECURITYFOCUS")
       div = soup.find("div", id="vulnerability")
       date_sf=""
       entries = []

       for span in div.find_all("span", class_="label"):
          td = div.find_all('td')[1:]

       cve_sf = td[4].text
       cve_sf = " ".join(line.strip() for line in cve_sf.split("\n"))
       
       i=0
       while(i<entry.count('CVE')):
          entries.insert(i,entry.split(" ", entry.count('CVE'))[i])
          if 'CVE-2017' not in entries[i]:
             i+=1
             continue
          date_nvd, cwe_id, cvss_score = nvd(entries[i])
         # date_nvd, cwe_id, cvss_score = nvd("CVE-2017-13083")

       #date_nvd = nvd(entry)

          if not date_nvd:
             i+=1
             continue
          else:

             if cvss_score == "NOT DEFINED":
                cvss_rating = "NOT DEFINED"
             else:
                 cvss_rating = "DEFINED"

             date_nvd = dt.strptime(date_nvd[0:10], "%Y-%m-%d").date()

             date_sf = td[10].text
             date_sf = "".join(line.strip() for line in date_sf.split("\n")) 
             month=""
             month = assign_month_number(date_sf[0:3])
             date_sf = date_sf[7:11]+"-"+date_sf[4:6]+"-"+month
             date_sf = dt.strptime(date_sf, "%Y-%d-%m").date()

             if cvss_rating == "DEFINED":
                cvss_rating = assign_cvss_rating(cvss_score)

             row=""
             if date_sf < date_nvd:
                status = "DELAY"
                delta = date_nvd - date_sf
                #delay = delay + (entry.count('CVE'))
                #number_vulnerabilities = number_vulnerabilities + (entry.count('CVE'))
                delay = delay + 1
                number_vulnerabilities = number_vulnerabilities + 1
                print(number_vulnerabilities,entries[i], cwe_id, cvss_rating, date_nvd, date_sf, "DELAY", delta.days, delay)
                row = ","+str(number_vulnerabilities)+","+entries[i]+","+cwe_id+","+cvss_rating+","+str(date_nvd)+","+str(date_sf)+","+status+","+str(delta.days)+","+str(delay)+"\n"
                file.write(bytes(row, encoding="ascii", errors="ignore"))
             else:
                status = "NO DELAY"
                #number_vulnerabilities=number_vulnerabilities + (entry.count('CVE'))
                number_vulnerabilities = number_vulnerabilities + 1
                print(number_vulnerabilities,entries[i], cwe_id, cvss_rating, date_nvd, date_sf, "NO DELAY", delay)
                row = ","+str(number_vulnerabilities)+","+entries[i]+","+cwe_id+","+cvss_rating+","+str(date_nvd)+","+str(date_sf)+","+status+","+""+","+str(delay)+"\n"
                file.write(bytes(row, encoding="ascii", errors="ignore"))
           
          i+=1  
                                                                                                    	
     except urllib.error.URLError as err:
         continue
     except urllib.error.URLError as err:
         continue

     #print(row, exploit_db_published[11:])
       
