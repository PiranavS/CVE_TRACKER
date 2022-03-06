from pandas.core.frame import DataFrame
import re
import smpl1
import ubuntu_cve_scrapes
import pandas as pd
import concurrent.futures
import itertools

def table(oper_sys_name,cve1,os_name,version) :
    

        #if os_name.startswith("Red Hat Enterprise Linux"):
            #rhel=1
        table = pd.DataFrame()

        if oper_sys_name.startswith('Red Hat'):

            with concurrent.futures.ThreadPoolExecutor() as executor:
                for file in executor.map(smpl1.tab_search, cve1,itertools.repeat(os_name),itertools.repeat(version)):
                    table = table.append(file,ignore_index=True)

                executor.shutdown(wait=True,cancel_futures=False)


            #print(table)

            #table = next(df_list, None)
            

                
            #table = smpl1.rh_scrape('CVE-2020-25660')
            #print(table)
            #os_name=os_name.rsplit(' ', 1)[0]
            #table = table[table['Platform'].str.contains(os_name,regex=False,na=False)]
            #table = table[table['Platform'].str.contains(version,regex=False,na=False)]
            #print(table)


        


        if oper_sys_name.startswith('Ubuntu'):
            table = pd.DataFrame()
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
                for file in executor.map(ubuntu_cve_scrapes.tab_search, cve1,itertools.repeat(version)):
                    table = table.append(file,ignore_index=True)

                executor.shutdown(wait=True,cancel_futures=False)


           
            
            
            
            #for cve in cves:
                #print(table)
                #if table.empty :
                    #table = ubuntu_cve_scrapes.tab_search(cve,version)
                #else:
                    #table = table.append(ubuntu_cve_scrapes.tab_search(cve,version))

        return table
            



