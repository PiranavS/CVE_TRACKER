import pandas as pd
from pandas.core.frame import DataFrame
from selenium import webdriver
import warnings

def ubu_scrape(cve):
    url = "http://ubuntu.com/security/" 
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    url = url+cve
    options = webdriver.FirefoxOptions()
    options.headless= True
    driver = webdriver.Firefox(options=options)
    driver.get(url)
    html = driver.page_source
    tables = pd.read_html(html)

    driver.close()
    table = tables[0]
    #print(table)
    table["Release"].replace({'trusty':'14.04 LTS (Trusty Tahr)','xenial':'16.04 LTS (Xenial Xerus)','bionic':'18.04 LTS (Bionic Beaver)','focal':'20.04 LTS (Focal Fossa)','groovy':'20.10 (Groovy Gorilla)','hirsute':'21.04 (Hirsute Hippo)','impish':'21.10 (Impish Indri)','jammy':'22.04 LTS (Jammy Jellyfish)'},inplace=True)
    #print(table)
    return table

def tab_search(cve,version):
    table = ubu_scrape(cve)
    patch = table[table['Release'].str.contains(version,regex=False,na=False)]
    patch.insert(0, 'CVE', cve)
    #print(cve," ",patch['Status'].values)
    return patch



    