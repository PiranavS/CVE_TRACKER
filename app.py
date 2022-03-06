import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import smp2
import pandas as pd
import textract
from tkinter import *
import glob

# initalise the tkinter GUI
root = tk.Tk()

root.geometry("1000x800") # set the root dimensions
root.pack_propagate(False) # tells the root to not let the widgets inside it determine its size.
root.resizable(0, 0) # makes the root window fixed in size.

# Frame for TreeView
frame1 = tk.LabelFrame(root, text="CVE Data")
frame1.place(height=500, width=1000)

# Frame for open file dialog
file_frame = tk.LabelFrame(root, text="Open File")
file_frame.place(height=100, width=400, rely=0.65, relx=0)

#Frame for text
text_frame = tk.LabelFrame(root,text = "Input Field")
text_frame.place(height=100, width=400, rely=0.65, relx=0.4)

#Textbox
entry1 = tk.Entry (text_frame,width = 50) 
entry1.pack()

# Buttons
button1 = tk.Button(file_frame, text="Browse A File", command=lambda: File_dialog())
button1.place(rely=0.65, relx=0.50)

button2 = tk.Button(file_frame, text="Load File", command=lambda: Load_table_data())
button2.place(rely=0.65, relx=0.30)

button3 = tk.Button(text_frame, text="Enter",command =lambda:retrieve_input() )

# The file/file path text
label_file = ttk.Label(file_frame, text="No File Selected")
label_file.place(rely=0, relx=0)




## Treeview Widget
tv1 = ttk.Treeview(frame1)
tv1.place(relheight=1, relwidth=1) # set the height and width of the widget to 100% of its container (frame1).

treescrolly = tk.Scrollbar(frame1, orient="vertical", command=tv1.yview) # command means update the yaxis view of the widget
treescrollx = tk.Scrollbar(frame1, orient="horizontal", command=tv1.xview) # command means update the xaxis view of the widget
tv1.configure(xscrollcommand=treescrollx.set, yscrollcommand=treescrolly.set) # assign the scrollbars to the Treeview Widget
treescrollx.pack(side="bottom", fill="x") # make the scrollbar fill the x axis of the Treeview widget
treescrolly.pack(side="right", fill="y") # make the scrollbar fill the y axis of the Treeview widget


def File_dialog():
    """This Function will open the file explorer and assign the chosen file path to label_file"""
    filename = filedialog.askopenfilename(initialdir="/",
                                          title="Select A File",
                                          filetype=(("PDF files", "*.pdf"),("All Files", "*.*")))
    label_file["text"] = filename
    return None


def Load_table_data():
    """If the file selected is valid this will load the file into the Treeview"""
    file_path = label_file["text"]
    oper_sys_name,cve1,os_name,version,orig = get_info(file_path)
    print(oper_sys_name)
    try:
       df = smp2.table(oper_sys_name,cve1,os_name,version)
       print(version)
       #print(df)
       files_present = glob.glob("log.xlsx")
       if not files_present:
        old_df=df
        old_df["ex_os_name"]=orig
        old_df['os_name']=os_name+" "+version
        drop_in = old_df.loc[old_df['Package'] == "Not Found"].index
        #print(drop_in)
        old_df=old_df.drop(drop_in)
        drop_in = old_df.loc[old_df['Package'] == "Not Found"].index
        old_df.to_excel("log.xlsx",index=False)
        print("Transfer done")
       else:
           old_df = pd.read_excel("log.xlsx")
           new_df = df
           new_df["ex_os_name"]=orig
           new_df['os_name']=os_name+" "+version
           drop_in = new_df.loc[new_df["Package"] == "Not Found"].index
           new_df=new_df.drop(drop_in)
           old_df = old_df.append(new_df,ignore_index=True)
           old_df = old_df.drop_duplicates(ignore_index=True)
           print(old_df)
           old_df.to_excel("log.xlsx",index=False)
           print("Retrieval and Transfer done")
    except ValueError:
        tk.messagebox.showerror("Information", "The file you have chosen is invalid")
        return None
    except FileNotFoundError:
        tk.messagebox.showerror("Information", f"No such file as {file_path}")
        return None

    clear_data()
    tv1["column"] = list(df.columns)
    tv1["show"] = "headings"
    for column in tv1["columns"]:
        tv1.heading(column, text=column) # let the column heading = column name

    df_rows = df.to_numpy().tolist() # turns the dataframe into a list of lists
    for row in df_rows:
        tv1.insert("", "end", values=row) # inserts each list into the treeview. For parameters see https://docs.python.org/3/library/tkinter.ttk.html#tkinter.ttk.Treeview.insert
    return None


def clear_data():
    tv1.delete(*tv1.get_children())
    return None

def retrieve_input():
    input = entry1.get()
    return input

def get_info(address):
    
        text = textract.process(address)
        #print(text)        
        words = text.split()
        i=0

        for x in words:
            words[i] = x.decode('utf-8')
            i=i+1

        cves = []
        for x in words:
            if x.startswith('CVE-'):
                if x in cves:
                    continue
                if x=='CVE-ID':
                    continue
                else:
                    cves.append(x)

        print(cves)
        #print(words)
        oper_sys_name=''
        flag=0
        for x in words:
            if x =='Host':
                flag=0

            if flag==1 :
                oper_sys_name = oper_sys_name +" "+ x
            
            if x == '-)':
                flag=1

        if(oper_sys_name != None):    
            oper_sys_name = oper_sys_name.strip()
            orig = oper_sys_name
            comp = oper_sys_name.split()

        try:
            version = comp[len(comp)-1] 
        except:
            oper_sys_name = retrieve_input()
            oper_sys_name = oper_sys_name.strip()
            comp = oper_sys_name.split()
            orig = oper_sys_name
            version = comp[len(comp)-1] 
            

        #print(comp)
        #print(version)
        os_name= ""
        for wor in comp:
            if wor == "Server":
                continue
            if wor==version:
                break
            os_name = os_name +' '+wor
        os_name=os_name.strip(" ")

        #print(os_name)
        num = 0
        for num in range(len(version)-1, -1, -1) :
            if version[num] == '.':
                break

        version = version[0:num]
        os_final = os_name+' '+version
        #print(os_final)
        #print(version)

        cve1=[]
        for cve in cves:
                cve=cve.rsplit(',', 1)[0]
                cve=cve1.append(cve)
        #print(cve1)

        return os_final,cve1,os_name,version,orig


root.mainloop()