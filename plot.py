import matplotlib.pyplot as plt
import numpy as np
import re

# open the performance file with read mode
f = open("performance", "r")

# read the file and filter out lines starting with [+]
lines = f.readlines()
lines = [line for line in lines if line.startswith('[+]')]


s = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[10])[0])
s1 = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[15])[0]) 
s2 = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[20])[0])
s3 = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[25])[0])
y = np.array([s/1000,s1/1000,s2/1000,s3])

s = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[8])[0])
s1 = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[13])[0]) 
s2 = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[18])[0])
s3 = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[23])[0])
y1 = np.array([s,s1,s2,s3])

s = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[7])[0])
s1 = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[12])[0]) 
s2 = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[17])[0])
s3 = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[22])[0])
y3 = np.array([s,s1,s2,s3])

s = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[9])[0])
s1 = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[14])[0]) 
s2 = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[19])[0])
s3 = float(re.findall(r'[-+]?(?:\d*\.*\d+)', lines[24])[0])
y4 = np.array([s,s1,s2,s3])
# convert the string to float numbers and save them into an array call y4
print(y)
print(y1)
print(y3)
print(y4)


x = np.array([0,1,10,100,1000,0])
ind = np.array([1,2,3,4])



fig, ax1 = plt.subplots()
ax1.set_xticks(range(6))
ax1.set_xticklabels(x)
ax1.plot(ind,y1,"bs-",label='Party Computation')
ax1.plot(ind,y,"b--o",label="Judge Computation")

ax1.plot(0,0)
ax1.plot(5,0)

ax1.set_ylabel("Computation (ms)")
ax1.set_xlabel("Number of Transcripts")
ax1.set_ylim([0,20])


ax2 = ax1.twinx()
ax2.plot(ind,np.log(y3),"-.d",label="Party Communication")
ax2.plot(ind,np.log(y4),":*",label="Judge Communication")
ax2.set_ylabel("Communication (log(bytes))")
ax2.set_ylim([0,15])

lines, labels = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax2.legend(lines + lines2, labels + labels2, loc='upper right')



fig.tight_layout()

plt.savefig("performance.png")
plt.show()
