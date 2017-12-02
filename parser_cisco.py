import bs4 as bs
import urllib.request
import os

from datetime import datetime as dt

file = open(os.path.expanduser("cisco.csv"), "wb")
header= ",Number of Vulnerabilities Found, CVE,CWE,CVSS,NVD Published,CISCO Published,Status,Attack Window (Days), Total Delays\n"
file.write(bytes(header, encoding="ascii", errors="ignore"))

delay = 0
number_vulnerabilities = 0

#source = urllib.request.urlopen("https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171004-ncs").read()
#soup = bs.BeautifulSoup(source, 'lxml')

def make_soup(file, db):

   if db == "NVD":
      source = open(file).read()

   elif db == "CISCO":
      source = urllib.request.urlopen(file).read() 

   soup = bs.BeautifulSoup(source, 'lxml')
   return soup

def assign_month_number(month):

  return {
   'January': '01',
   'February': '02',
   'March': '03',
   'April': '04',
   'May': '05',
   'June': '06',
   'July': '07',
   'August': '08',
   'September': '09',
   'October': '10',
   'November': '11',
   'December': '12'

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

soup_nvd = make_soup("nvdcve-2.0-2017.xml", "NVD")
entry = soup_nvd.find_all("entry")

for data in entry:
   try:
      product = data.find("vuln:product").text
      cve = data.find("vuln:cve-id").text

      if "cisco" in product:
          date_nvd = data.find("vuln:published-datetime").text
          cwe_id = data.find("vuln:cwe").get("id")
          cvss_score = data.find("cvss:score").text
          cvss_rating = assign_cvss_rating(cvss_score)
          for reference in data.find_all("vuln:reference"):
            if "tools.cisco.com" in reference.text:
              #print(cve, reference.text)
              soup_cisco = make_soup(reference.text, "CISCO")
              div = soup_cisco.find_all("div", class_="divLabelContent")
              publish_cisco = div[1].text
              #print(publish_cisco)
              publish_date_cisco = publish_cisco.split()
              #print(date_cisco)
              year = publish_date_cisco[0]
              #print(year)
              #print(date_cisco[1])
              month = assign_month_number(publish_date_cisco[1])
              #print(month)
              day = publish_date_cisco[2]
              date_cisco = year+"-"+month+"-"+day
              #print(date_cisco)
              date_nvd = dt.strptime(date_nvd[0:10], "%Y-%m-%d").date()
              date_cisco = dt.strptime(date_cisco, "%Y-%m-%d").date()

              cvss_rating = assign_cvss_rating(cvss_score)

              row=""
              if date_cisco < date_nvd:
                 status = "DELAY"
                 delta = date_nvd - date_cisco
                 delay = delay + 1
                 number_vulnerabilities = number_vulnerabilities + 1
                 print(number_vulnerabilities,cve, cwe_id, cvss_rating, date_nvd, date_cisco, "DELAY", delta.days, delay)
                 row = ","+str(number_vulnerabilities)+","+cve+","+cwe_id+","+cvss_rating+","+str(date_nvd)+","+str(date_cisco)+","+status+","+str(delta.days)+","+str(delay)+"\n"
                 file.write(bytes(row, encoding="ascii", errors="ignore"))
              else:
                 status = "NO DELAY"
                 number_vulnerabilities=number_vulnerabilities + 1
                 print(number_vulnerabilities,cve, cwe_id, cvss_rating, date_nvd, date_cisco, "NO DELAY", delay)
                 row = ","+str(number_vulnerabilities)+","+cve+","+cwe_id+","+cvss_rating+","+str(date_nvd)+","+str(date_cisco)+","+status+","+""+","+str(delay)+"\n"
                 file.write(bytes(row, encoding="ascii", errors="ignore"))

   except:
      continue

