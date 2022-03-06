from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
import pandas as pd
import time
import warnings
from selenium.webdriver.support import expected_conditions as EC 
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.ui import Select

def rh_scrape(cve):
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    url = 'https://access.redhat.com/security/cve/'
    url = url+cve
    options = webdriver.FirefoxOptions()
    options.headless= True
    driver = webdriver.Firefox(options=options)
    driver.get(url)
    time.sleep(2)
    driver.execute_script("window.scrollTo(0,document.body.scrollHeight)")
    loop=1
    time.sleep(2)
    html = driver.page_source
    tables = pd.read_html(html)
    f_table = tables[0]

    while loop:
            elm = driver.find_elements_by_id('DataTables_Table_0_next')
            wait = WebDriverWait(driver, 10)
            try:
                wait.until(EC.visibility_of(elm[0]))
            except:
                break
            time.sleep(2)
            driver.execute_script("arguments[0].click();", elm[0])
            html = driver.page_source
            tables=pd.read_html(html)
            f_table=pd.concat([f_table,tables[0]],ignore_index=True)
            #print(tables[0])
            elm = driver.find_elements_by_id('DataTables_Table_0_next')
            flag = elm[0].get_attribute('tabindex')


            if flag == '-1':
                loop = 0
                break

            


    driver.close()

    return f_table
 

def tab_search(cve,os_name,version):

    #os_alt ='RHEL'+' '+version
    #os_alt1 = 'RHEL'+' -'+version
    os_final = os_name+" "+version
    table = rh_scrape(cve)
    os_name=os_name.rsplit(' ', 1)[0]
    #table1 = table[table['Platform'].str.contains(os_name,regex=False,na=False)]
    #if rhel:
        #table2 = table[table['Platform'].str.contains(os_alt,regex=False,na=False)|table['Platform'].str.contains(os_alt1,regex=False,na=False)]
        #table1 = pd.concat([table1,table2])
    patch = table[table['Platform'].str.contains(os_final,regex=False,na=False)]
    pd.set_option('display.max_colwidth', None)
    patch.insert(0, 'CVE', cve)
    print(cve)
    #print(patch)
   
    if not patch[['State','Package']].values.any():
        print("Not found")
        patch = patch.append({'CVE':cve,'Platform':os_final,"Package":"Not Found","State":"Not Applicable","Errata":"Not applicable","Release Date":"Not Applicable"},ignore_index=True)
        #print(patch)
    else:
        #print(patch[['State','Package']].values)
        print("Found")


    return patch
        
