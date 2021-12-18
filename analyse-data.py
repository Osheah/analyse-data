#analyse-data
'''
Analyse Data from memory dump or another data set

This assignment is to analyse data. For this I used Seamus's Dowling timeline file base-rd-01-supertimeline.csv which can be found in the Teams files for the course IDR (part of GMIT's certificate in Cybersecurity). I have not uploaded that file to github in this repo though you can find it here. You will have to login to GMIT to access it. The file is stored in the same directory that contains this notebook.

'''
#import the packages
# imports
import pandas as pd # main package for dataframes
import numpy as np 
import matplotlib.pyplot as plt
#%matplotlib inline 
# magic function to show plots inline in the notebook
import datetime as dt
import matplotlib.ticker as ticker
import seaborn as sns
import re 
from collections import Counter
#Firstly, read the file. I looked at the csv headers before loading it to pandas 
# useful links https://github.com/jleaniz/misc/blob/master/timeilne_analysis.ipynb
# cols are date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
#filename = 'baserd01-filesystem-timeline.csv' # i was going to use this file but then went with the super timeline for more varied data
filename = 'base-rd-01-supertimeline.csv'
df = pd.read_csv(filename, sep=',')
print(df)
#check the shape of the dataframe
print(df.shape)
#This is a massive file. Hundreds of thousands of rows and 17 columns
print(type(df)) # its a dataframe
print(df.dtypes) # check the types of the columns in the dataframes
# Almost all the columns are not statistical including the date column

#check the first few values
print(df.head())
#check the last few values

print(df.tail())
#check the column names

print(df.columns)

#check the unique values in each column, to get a quick overview.

for column in df:

    print(column, "has unique values\n", df[column].unique(), "\n")

    print(column, "has ", df[column].nunique(), " unique values\n")
#Drop the columns that don't have interesting stuff - have a quick look first.

todrop=[]

for column in df:

    if (df[column].nunique() == 1):

        #print(column)

        todrop.append(column)

print(df[todrop].head())
for column in df:
    if (df[column].nunique() == 1):
        df.drop(column,axis=1, inplace =True)
        
print(df)
#check the shape again

print(df.shape) # cols are now 13
#Date

#recap

print(df['date'].unique())

print(df['date'].nunique())
#All 15 dates are in August and September 2018.
#Time

#recap

print(df['time'].unique())

print(df['time'].nunique())
#wide range of time values (34868 of them). 24 hour clock used and seconds recorded.

#Date and time should be in datetime format so join them
#Make datetime

df['datetime'] = df['date']+"/"+df['time']

print(df['datetime'])
df['datetime'] = pd.to_datetime(df['datetime'], format="%m/%d/%Y/%H:%M:%S") # format is mm/dd/yyyy/hh:mm:ss
print(df['datetime']) # now in datetime format
print(df['datetime'].min()) # earliest time
#earliest date is aug 2018 just after midnight

print(df['datetime'].max()) # latest time
#latest date is sept 2018 just before midnight

#The timeframe is 2 weeks of data

print(df['datetime'].max() - df['datetime'].min())
# you can get the various times out with datetime functions if you want to
print("the year is \n",df['datetime'].dt.year)
print("the month is \n", df['datetime'].dt.month)
print("the day is \n",df['datetime'].dt.day) 
'''
MACB

The MACB notation refers to window events for files/directories. See the flyer below. It looks like the '...' refers to no file change. The letter M, A, C, B refers to the file being modified, accessed, changed or created.
Seamus Dowling's slides on timelining note the following
Timestamp metadata

    M –Data content last modified
    A –Data content last accessed
    C –Metadata content changed on MFT
    B –Metadata first created (Birth)

'''
# recap
print(df['MACB'].unique())
print(df['MACB'].nunique())
#There are 15 different combos of MACB. This is useful for finding newly created files and deleted files.
#Source

# recap

print(df.source.unique())
print(df.source.nunique())

#This looks like info regarding to where the file came from e.g events, web history, logs, file, registry, pe?, link, olecf?, meta data, recycling bin. pe is portable executable file and olecf is an embedded object (thanks google).

#There are 10 different types of sources of data
#Sourcetype
# recap
print(df.sourcetype.unique())
print(df.sourcetype.nunique())
#This looks like a sub division of source eg. winevtx is probably windows event files and part of event data. Chrome cookies is part of web history as is Chrome Cache and Chrome History (I imagine). Do a quick check to see if thats true

print(df[['source', 'sourcetype']][(df['source']=='WEBHIST') & ((df['sourcetype']=='Chrome History'))])
print(df[['source', 'sourcetype']][(df['source']=='WEBHIST') & ((df['sourcetype']=='Chrome Cookies'))] )

#There are 29 source types. I wonder how they brake down by source?

print(df.groupby(['source'])['sourcetype'].value_counts())
      
#All evt are windows eventx artifacts, webhist contains cache, cookie and history from chrome etc. Most rows are windows event logs.

#Type
# recap
print(df.type.unique())
print(df.type.nunique())
#Type appears to be the readable form of MACB.

#however there are not the same number of unique MACB's as types, so maybe it depends on where MACB code is located.

print(df.type.nunique()-df.MACB.nunique())

print(df.MACB.unique())

#Short

#recap 

print(df.short.unique())

print(df.short.nunique())
#This is an array with strings that have info. This might have interesting data. The first array looks like event numbers. The strings do not fully show in the notebook and are truncated (which is annoying- though it crashes if its changed to show). It might be useful to export this column to csv and then read it as a new dataframe with a separator.         

#Desc

#recap 

print(df.desc.unique())

print(df.desc.nunique())
#This looks to be the same as short but in a different format and more verbose

print(df[['short', 'desc']])
#There is extra info in the desc regarding the string e.g. Source Name: Microsoft-Windows-PushNotification-PlatformStrings: desc is more verbose

#I checked and 107 is 0x006b in hex so the first part is dec\hex which can be split out. The second part is a string which I'll split out. I'll use short instead of desc as its shorter.
#check to see if the new columns are there (id_dec, id_hex, short_string)

print(df.columns) # the new cols id_hex, id_dec and short_string are present
print(df.head()) # check how it looks

#Filename

#recap

print(df.filename.unique()[0:10]) # its too long so i'll just print out a few

print(df.filename.nunique())

#An array with the path to a filename event view log. Interesting. This could be split pull out file path details.

#Lots of unique filenames
#inode

print(df.inode.unique())

print(df.inode.nunique())



#Not sure what to do with that info.
#Format

#recap

#print(df.format.unique())

print(df.format.nunique())



#An array of categories with sub categories. Is it similar to source?

print(df.groupby(['source'])['format'].value_counts())

#Appears to be more finely tuned than source, source is a category and format is sub category. All evt are winevtx's.
#Extra

#recap

print(df.extra.unique()[0:5]) # too much info to print

print(df.extra.nunique())

#This has lots of potentially useful information

print(df.extra.head())

#After looking over this it seems that desc has the majority of the data in the dataframe and additional data is in extra. Its hard to see in jupyter notebook cause of the elipses... (which are also there when viewed in vscode). I'll try and list them out for a look.

desc_lst = df.desc.to_list() # look at desc list

for item in desc_lst[0:10000:500]: # just look at a sample as file is big

    print("\n", item)

extra_lst = df.extra.to_list() # look at extra list

for item in extra_lst[0:10000:1000]: # dont print them all out as file is big.

    print("\n", item)

#Extra has keys and values. How can i access the keys in his array? try splitting on ';'

df_extra_split = df.extra.str.split(";", expand=True)


for c in range(5, 101):

    df_extra_split.drop([c], axis=1, inplace=True)


df_extra_split.columns = ['extra_recovered', 'extra_sha256_hash', 'extra_strings_parsed', 'extra_user_sid', 'extra_xml_string']

df_extra_split

df_extra_split.extra_recovered.replace(to_replace="recovered: ", value="", regex=True, inplace=True)

df_extra_split.extra_sha256_hash.replace(to_replace="sha256_hash: ", value="", regex=True, inplace=True)

df_extra_split.extra_strings_parsed.replace(to_replace="strings_parsed: ", value="", regex=True, inplace=True)

df_extra_split.extra_user_sid.replace(to_replace="user_sid: ", value="", regex=True, inplace=True)

df_extra_split.extra_xml_string.replace(to_replace="xml_string: ", value="", regex=True, inplace=True)

print(df_extra_split)

#Add the columns to df

df =pd.concat([df, df_extra_split], axis =1)

print(df.head())

#check if the new cols are there.

print(df.columns) # the extra_recovered, extra_sha256_hash, extra_stings_parsed, extra_user_sid and extra_xml_string are in the dataframe df

#Have a look at the new columns

for column in df[['extra_recovered', 'extra_sha256_hash', 'extra_strings_parsed', 'extra_user_sid', 'extra_xml_string']]:

    print(df[column].nunique())

for column in df[['extra_recovered', 'extra_sha256_hash', 'extra_strings_parsed', 'extra_user_sid', 'extra_xml_string']][0:10000:5000]:

    print("\n",column, 'has ', df[column].nunique(), ' values with sample shown below \n ', df[column].unique(), 'v')

    

# just view a sample as its a big file. 

#Look at some statistical info

print(df.describe())

#This does not produce anything useful here. Only inode has statistical info but its not useful to analyse it that way.

#I've added a few cols which changed the shape

print(df.shape) # quick look at the shape

#revisit filename

#Going back to filename - pull out the user from the filename

filename_users = df.filename.str.split(r"\\")

                                  

print(filename_users.str[3].unique())

df['filename_users'] = filename_users.str[3]

print(df['filename_users'].unique())

#spsql looks like a sql account maybe. The workstation user is tdungan. I don't know what .shieldbase extention is.

#Lets look at spsql user


spsql_user = df[df['filename_users']=='spsql'] # cant see it in the notebook with the ...

#print(spsql_user)

for u in spsql_user['desc'][0:10000:500].items(): # too much info take sample

    print(u)


#Lots of no values stored in keys. Otherwise I'm none the wiser. Lets look at the Temp user.

temp_user = df[df['filename_users']=='Temp'] # cant see it in the notebook with the ...

print(temp_user)

for u in temp_user['desc'].items():

    print(u)



#The PE files are interesting. Lets look at the Public user

public_user = df[df['filename_users']=='Public'] # cant see it in the notebook with the ...

print(public_user)

for u in public_user['desc'].items():

    print(u)


#Public user seems to be for Internet access as its all about Chrome. Lets look at the long string user.

string_user = df[df['filename_users']=='S-1-5-21-3445421715-2530590580-3149308974-1193'] # cant see it in the notebook with the ...

print(string_user)

for u in string_user['desc'].items():

    print(u)


#tdungan is Timothy Dungan and he saved sawaguchi's backup log which is deleted.

string_user = df[df['filename_users']=='rsydow-a'] # cant see it in the notebook with the ...

print(string_user)

for u in string_user['desc'].items():

    print(u)


#I dont know what rsydow-a is. Lots of Unknown sourcetype.
#Prefetch

#Prefetch is a good place to look for suspicous stuff

print(df[['sourcetype', 'filename']][df.sourcetype=='WinPrefetch'])

#Pull out the prefetch information. For this I split df into a prefetch dataframe for just prefetch info.

# trouble with regex bad escape at \C so i'll just remove \

# hide the warnings for now

import warnings 

warnings.filterwarnings('ignore')


myregex = "OS:E:\\C\\Windows\\prefetch\\"



prefetch = df.loc[df['filename'].str.startswith(myregex)] 

prefetch['exe'] =prefetch['filename'].str.replace('\\','').str.replace('OS:E:CWindowsprefetch', '').str.split('-').str[0]

prefetch['pf'] = prefetch['filename'].str.replace('\\','').str.replace('OS:E:CWindowsprefetch', '').str.split('-').str[1] 

print(prefetch)



# i could have filtered by sourcetype instead of using prefetch dataframe


print(prefetch['exe'].unique()) # look at unique exe's

#Items to note include schtasks, powershell, wmiprvse, rdpclip, wsmprovhost, taskkill. Use SAN's filtering and that pdf on excel hunting to look for suspicious items in prefetch data.

# https://sansorg.egnyte.com/dl/ZkAyckjFTI

# list of suspicious items taken from SANS Find Evil poster and from this pdf https://www.giac.org/paper/gcih/10588/hunting-log-data-excel/104581

# to just get at.exe use '^at.exe' 

evil_things = ["$C", "Admin$", "psexec.exe", "PsExec", "psexesvc", "^at.exe", "schtasks.exe", "^sc.exe", "wmic.exe", "wmiprvse.exe"

       "scrcons.exe", "mofcomp.exe", "powershell.exe","PowerShell" "wsmprovhost.exe", "find.exe", "ipconfig.exe", "reg.exe", "neti.exe", 

              'tasklist.exe', '^cmd.exe', '^net.exe', 'pe.exe']

# uppercase it as its capitalised in prefetch

evil_things = [e.upper() for e in evil_things]

prefetch.columns # just checking the column names

for evil_thing in evil_things:

    if prefetch[prefetch['exe'].str.contains(evil_thing)].empty:

        continue

    else:

        print("Evil found for ", evil_thing, prefetch[['datetime', 'exe']][prefetch['exe'].str.contains(evil_thing)]) 

#ipconfig was run at 2018-09-05 11:55:31 - whats that about?

# to get rid of row ... so i can see things

#pd.set_option('display.max_row',1000) # still not working right :(

# lets look around the ipconfig execution time

start_time = '2018-09-05 11:55:00' # start a bit before ipconfig time of 2018-09-05 11:55:31

end_time = '2018-09-05 11:56:00' # end a bit after ipconfig time

mask = (df['datetime'] >= start_time) & (df['datetime'] <= end_time) 

print(df.loc[mask])

    
'''
Sample analysis:

wmiprvse.exe was run; spsql user is doing something; RDP client disconnected warnings - thats remote desktop; and a few seconds later 09/05/2018 11:55:18 RDP client disconnected warning is given. Then cosa clients ran (think thats for mobiles - maybe connecting phone to desktop?) followed by a 'logon office click' to run service monitor; dllhost.exe run 44 times, runtimebroker.exe was executed a lot. Rdp client warning occurred again then ipconfig run. After that the remote desktop connection attempt was tried at event 141380 09/05/2018 11:55:54 which succeeded at event 141382 09/05/2018 11:55:54 - Lots of Microsoft stuff was scheduelled so it might just be an update or it might not. There was also some game related programmes executed. It would be better to use a SIEM to analyse this type of information.

# https://social.technet.microsoft.com/wiki/contents/articles/37870.remote-desktop-client-troubleshooting-disconnect-codes-and-reasons.aspx

# codes for remote desktop connections are listed in the link above

Powershell was run three times in rapid succession on the 2018-09-06 20:30:00 - scheduled tasks were set up at 2018-09-06 20:39:16 possibly for persistence - check out data on 2018-09-06 round 20.30

'''
start_time = '2018-09-06 20:29:00'

end_time = '2018-09-06 20:50:00'

mask = (df['datetime'] > start_time) & (df['datetime'] <= end_time) 

df.loc[mask]

start_index =df.index[df.index[df['datetime'] > start_time]].min()

end_index =df.index[df.index[df['datetime'] <= end_time]].max()


for e in df.iloc[range(int(start_index), int(end_index)+1)].items():

    print(e)

# still can see what is going on - would be better in a siem here.

print(df['filename_users'].unique()) # quick look at users again

#Look at the number of sourcetypes per filename user

print(df[['sourcetype', 'filename_users']].groupby('filename_users').count().sort_values('sourcetype', ascending=False))


#Most activity is with system32 followed by spsql then Tim. Identify suspicious items

#loop over the other cols for suspicious stuff

print(df.sourcetype.unique())

# loop over some other relevant cols and see if suspicious content mentioned (already got the prefetch done)

found_evil=[]

for column in df[['MACB', 'source', 'sourcetype', 'type', 'short', 'desc', 'filename', 'extra']]: 

    for evil_thing in evil_things:

        if df[df[column].str.contains(evil_thing, na=False)].empty:

            continue

        else:

            print("Evil found for ", evil_thing, df[df[column].str.contains(evil_thing, na=False)]) 

            found_evil.append(df[df[column].str.contains(evil_thing, na=False)])

#This lists potential problems so maybe save it?

found_evil_df = pd.DataFrame(found_evil) 

    

# saving the dataframe 

found_evil_df.to_csv('found_evil.csv') 

print('done')

#Another quick look

print(type(found_evil))

print(len(found_evil))


#MACB revisited

#just having a look at type and MACB again

print(df.type.unique() )

print(df.MACB.unique())

#Items with MACB in MACB column indicate newly created files

# created files

created_files = df.loc[df['MACB'].str.contains('MACB')]

print(created_files.head())

#created_files['short string']

print(created_files.MACB.count())

#

print(len(df[df['MACB']=='MACB'])) # quick check

#Theres a few hundred newly created files

created_files.columns

created_files[["date", "MACB", "type"]]

#visualise created files

on_date = '08/28/2018'

created_files_on_date = created_files[created_files['date'] == on_date].copy()

print(created_files_on_date)

#Plot created files by date

#dates = Counter(created_files.date.apply(lambda x: x.strftime('%d-%m-%Y')) )

dates = Counter(created_files.date)

#print(dates)

counts = dates

index = []

data = []


for k,v in counts.items():

    index.append(k)

    data.append(v)

ts = pd.Series(data, index)

figsize=(15, 10)

ts.plot(kind="barh", title="Bar chart of created files per date")

plt.xlabel('Number of created files')

plt.ylabel('date')

plt.show()



#Loads of files created on the 28th of August 2018. Look at that date.

# lots of activity on the 28th

df[['date']]


check_date = r"08/28/2018"

created_files_check_date = created_files[created_files['date']==check_date].copy()


print(created_files_check_date.head())

print(len(created_files_check_date)) # 378 created files on that date

#Plot the created files on Aug 28th

dates = Counter(created_files_on_date.time)

#print(dates)

counts = dates

index = []

data = []



for k,v in counts.items():

    index.append(k)

    data.append(v)

ts = pd.Series(data, index)

figsize=(15, 10)

ts.plot(title="Bar chart of created files on date " + on_date)

plt.xlabel('Number of created files')

plt.ylabel('on date '+ on_date)



plt.show()


#around 21:40 ish lots of files created. Narrow down the time and have a look.

start_time = '2018-08-28 21:39:40'

end_time = '2018-08-28 21:42:00'

mask = (df['datetime'] > start_time) & (df['datetime'] <= end_time) 

print(created_files.loc[mask])

# still can see what is going on - would be better in a siem here.

created_files.loc[mask]

print(created_files.loc[mask].filename.unique()) # stuff sent to g timeline output - data exfiltration? 

#What is that file? It looks like an artifact collector MFTECmd's output.
#Type revisited

#Have a quick look at MACB and type

print(df[['MACB', 'type']].groupby('type').count().sort_values("MACB", ascending=False))

#pd.set_option('display.max_colwidth',1000)# remove elipses to see filename

## check the file downloaded type

print(df.filename[df.type=='File Downloaded'].unique()) # its web history

#What's launch time?

print(df.filename[df.type=='Launch time'].unique()) # 

#Plots

#Do some plots
#MACB Count

# plot 

ax = sns.countplot(x="MACB", data=df)

plt.title("Count plot of MACB column")


#Most entires are 'M...' - hard to see others so plot without 'M...' for a quick look

# drop M... to see what the others look look like

sns.countplot(data=df.loc[df['MACB']!="M..."], x='MACB')

plt.title("Count plot of MACB column (without M...)")

plt.xticks(rotation=90)
plt.show()

#After 'M...', '..C.' and '.A..' are the most frequent which are last visited time and Metadata Modification Time (see below)

print(df.groupby(['type', 'MACB'])['MACB'].count().sort_values(ascending=False))

#Plot the counts of 'type' column

sns.countplot(data=df, x='type')

plt.xticks(rotation=90)

plt.title("Count plot of type column")

#content modification time swamps things so plot without it to have a look

sns.countplot(data=df.loc[df['type']!="Content Modification Time"], x='type')

plt.xticks(rotation=90)

plt.title("Count plot of type column (without Content Modification Time)")
plt.show()

#maybe plot the type by date?

print(df.type.unique() )# checking type values

# plot 

fig, ax = plt.subplots(figsize=(12,4))

df.groupby(['date'])['type'].count().plot(ax=ax, kind='bar')

plt.title("Count plot of type grouped by date")

plt.xlabel("date");  # custom x label using matplotlib

plt.ylabel("Count of Type");

plt.title('count of type by date')

plt.show()



#Not sure that is a useful plot. Lots of types used on Aug 28 and 5/6 of Sept. Not much types used on earlier dates in Aug.

#Loop through the columns and get their pivot counts

for column in df:

    print(column, "\n", df[column].value_counts(), "\n")

#Hist plots

#Try histograms

df.source.hist(bins=10)

plt.title('histogram of counts by source')

plt.xticks(rotation=90)
plt.show()

#Loop through certain cols to create various histograms

for column in df[['date', 'MACB', 'source', 'sourcetype', 'type', 'format']]:

    print(column)

    df[column].hist(bins=10)

    plt.title('histogram of counts by '+column)

    plt.xticks(rotation=90)

    plt.show()

#Countplots

#Create some countplots with seaborn

for column in df[['date', 'MACB', 'source', 'sourcetype', 'type', 'format']]:

    print(column)

    ax = sns.countplot(x=column, data=df)

    plt.title('count plot of '+column)

    plt.xticks(rotation=90)

    plt.show()

print(df.sort_values(by='date')) # python is useful for sorting 

'''
Conclusion

In conclusion you can do a lot of analysis on log data with python. In particular it gives you an overall feel for the data. This is especially useful when the data is so large as in this file.
'''









