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
import time
import os
from selenium import webdriver
from datetime import datetime as dt

file = open(os.path.expanduser("microsoft.csv"), "wb")
header= ",Number of Vulnerabilities Found, CVE,CWE,CVSS,NVD Published,MSFT Published,Status,Attack Window (Days), Total Delays\n"
file.write(bytes(header, encoding="ascii", errors="ignore"))

delay = 0
number_vulnerabilities = 0

def make_soup(file, db):

   if db == "NVD":
      source = open(file).read()

   elif db == "MICROSOFT":
      browser = webdriver.PhantomJS()
      browser.get(file)
      time.sleep(3)
      source = browser.page_source
      browser.close() 

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

      if "microsoft" in product:
          date_nvd = data.find("vuln:published-datetime").text

          try:
             cwe_id = data.find("vuln:cwe").get("id")
          except:
             cwe_id = "NOT DEFINED"
          try:
             cvss_score = data.find("cvss:score").text
          except:
             cvss_score = "NOT DEFINED"

          if cvss_score == "NOT DEFINED":
             cvss_rating = "NOT DEFINED"
          else:
             cvss_rating = "DEFINED"

          if cvss_rating == "DEFINED":
             cvss_rating = assign_cvss_rating(cvss_score)
         # print(cve, date_nvd, cwe_id, cvss_score, cvss_rating)
          for reference in data.find_all("vuln:reference"):
            if "portal.msrc.microsoft.com" in reference.text:
             # print(cve, reference.text)

              soup_msft = make_soup(reference.text, "MICROSOFT")
             # print(soup_msft)
              date_msft = soup_msft.find("p", class_="ng-binding")
            #  print(date_msft.text[20:30])

              date_nvd = dt.strptime(date_nvd[0:10], "%Y-%m-%d").date()
              date_msft = dt.strptime(date_msft.text[20:30], "%m/%d/%Y").date()
            #  print(date_nvd, date_msft)

              row=""
              if date_msft < date_nvd:
                 status = "DELAY"
                 delta = date_nvd - date_msft
                 delay = delay + 1
                 number_vulnerabilities = number_vulnerabilities + 1
                 print(number_vulnerabilities,cve, cwe_id, cvss_rating, date_nvd, date_msft, "DELAY", delta.days, delay)
                 row = ","+str(number_vulnerabilities)+","+cve+","+cwe_id+","+cvss_rating+","+str(date_nvd)+","+str(date_msft)+","+status+","+str(delta.days)+","+str(delay)+"\n"
                 file.write(bytes(row, encoding="ascii", errors="ignore"))
              else:
                 status = "NO DELAY"
                 number_vulnerabilities=number_vulnerabilities + 1
                 print(number_vulnerabilities,cve, cwe_id, cvss_rating, date_nvd, date_msft, "NO DELAY", delay)
                 row = ","+str(number_vulnerabilities)+","+cve+","+cwe_id+","+cvss_rating+","+str(date_nvd)+","+str(date_msft)+","+status+","+""+","+str(delay)+"\n"
                 file.write(bytes(row, encoding="ascii", errors="ignore"))

   except:
      continue

#browser = webdriver.PhantomJS()
#browser.get("https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0005")
#time.sleep(3)
#htmlSource = browser.page_source
#browser.find_element_by_xpath('//*[@type="checkbox"]').click()
#browser.find_element_by_xpath("//input[@type='button' and @value='Accept']").click()






