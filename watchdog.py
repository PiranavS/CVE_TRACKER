import notif_creater
import pandas as pd
import smpl1
import ubuntu_cve_scrapes
import notif_creater



data = pd.read_excel("log.xlsx")
print(data)
#data = data[(data['State']=='Affected') |(data['Status']=="Needed")|(data['Status']=="Needs Triage")|(data['Status']=="Needed")|(data["Status"]=='Deferred')|(data['Status']==("Pending"))]
#print(data)
#print(data[["CVE","os_name"]])
def runcheck():
 for ind in data.index:
  if data['os_name'][ind].startswith('Red Hat'):
     cve_data = smpl1.rh_scrape(data['CVE'][ind])
     #print(cve_data)
     cve_data = cve_data[(cve_data['Platform']==(data['Platform'][ind]))&(cve_data['Package']== data['Package'][ind])]

  if data['os_name'][ind].startswith("Ubuntu"):
     cve_data = ubuntu_cve_scrapes.ubu_scrape(data['CVE'][ind])
     #print(cve_data)
     os = data['os_name'][ind]
     os = os.split()[0]+" "+os.split()[2]
     #print(os)
     cve_data = cve_data[(cve_data['Release'].str.contains(os,regex=False,na=False))]

  print(cve_data)
  flag = 0
  try: 
     if cve_data['Status'].str.contains("Released",regex=False,na=False) :
        flag =1 
  except:
     if cve_data['State'].iloc[0]=="Fixed":
         flag =1

  if flag==1:
     #os = cve_data["Release"].iloc[0]
     #print(type(os))
     notif_creater.send_notif(data["CVE"][ind]+": "+ data["ex_os_name"][ind])

    

