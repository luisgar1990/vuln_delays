import bs4 as bs
import urllib.request
import os

from datetime import datetime as dt

file = open(os.path.expanduser("exdb.csv"), "wb")
header= ",Number of Vulnerabilities Found, CVE,CWE,CVSS,NVD Published,EXDB Published,Status,Attack Window (Days), Total Delays\n"
file.write(bytes(header, encoding="ascii", errors="ignore"))

cve_source = urllib.request.urlopen("http://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html").read()
cve_soup = bs.BeautifulSoup(cve_source, 'lxml')
url = 'https://www.exploit-db.com/exploits/'
delay = 0
number_vulnerabilities = 0

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
                  
    elif db =="EXPLOITDB":
       source = urllib.request.urlopen(file).read()
                               
    soup = bs.BeautifulSoup(source, 'lxml')
    return soup

def nvd(cve_exdb):
    print("ENTERED FUNCTION WITH", cve_exdb)
    #print(cve_exdb)

    soup = make_soup('nvdcve-2.0-2017.xml', "NVD")
    entry = soup.find_all("entry")
    
    #cve_sf = cve_sf.split(" ", 1)[0]
    #print(cve_sf)
    
    for data in entry:
       cve = data.find("vuln:cve-id").text

       if (cve == cve_exdb):
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
       exploit_db = td[0].text
       exploit_db_id = exploit_db[11:]
       soup = make_soup(url+exploit_db_id, "EXPLOITDB")
       exploit_db_table = soup.table
       if not exploit_db_table:
           continue
       entries = []
       exploit_db_table_row = exploit_db_table.find('tr')
       exploit_db_table_column = exploit_db_table_row.find_all('td')
       exploit_db_date = exploit_db_table_column[2].text

       i=0
       while(i<entry.count('CVE')):
          entries.insert(i,entry.split(" ", entry.count('CVE'))[i])
          if "CVE-2017" not in entries[i]:
             i+=1
             continue
          date_nvd, cwe_id, cvss_score = nvd(entries[i])

          if not date_nvd:
             i+=1
             continue
          else:

             if cvss_score == "NOT DEFINED":
                cvss_rating = "NOT DEFINED"
             else:
                 cvss_rating = "DEFINED"

             date_nvd = dt.strptime(date_nvd[0:10], "%Y-%m-%d").date()
             date_exdb = dt.strptime(exploit_db_date[11:], "%Y-%m-%d").date()

             if cvss_rating == "DEFINED":
                cvss_rating = assign_cvss_rating(cvss_score)

             row=""
             if date_exdb < date_nvd:
               status = "DELAY"
               delta = date_nvd - date_exdb
               delay = delay + 1
               number_vulnerabilities = number_vulnerabilities + 1
               print(number_vulnerabilities,entries[i], cwe_id, cvss_rating, date_nvd, date_exdb, "DELAY", delta.days, delay)
               row = ","+str(number_vulnerabilities)+","+entries[i]+","+cwe_id+","+cvss_rating+","+str(date_nvd)+","+str(date_exdb)+","+status+","+str(delta.days)+","+str(delay)+"\n"
               file.write(bytes(row, encoding="ascii", errors="ignore"))
             else:
               status = "NO DELAY"
               number_vulnerabilities=number_vulnerabilities + 1
               print(number_vulnerabilities,entries[i], cwe_id, cvss_rating, date_nvd, date_exdb, "NO DELAY", delay)
               row = ","+str(number_vulnerabilities)+","+entries[i]+","+cwe_id+","+cvss_rating+","+str(date_nvd)+","+str(date_exdb)+","+status+","+""+","+str(delay)+"\n"
               file.write(bytes(row, encoding="ascii", errors="ignore"))

          i+=1
                                                                                                               	
     except urllib.error.URLError as err:
         continue
     except urllib.error.URLError as err:
         continue

     #print(row, exploit_db_published[11:])
       
