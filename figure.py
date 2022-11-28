import matplotlib.pyplot as plt
from numpy import log
import re

import matplotlib_latex_bridge as mlb

mlb.setup_page(**mlb.formats.article_letterpaper_10pt_singlecolumn)
mlb.figure_columnwidth()

y,y2=[],[]
i=0
commu=[]
avow_commu=[]
with open("performance") as file:
    while (line := file.readline().rstrip()):
        if(line.startswith("[+]")):
            
            n=re.findall(r"[-+]?(?:\d*\.\d+|\d+)",line)
            print(n)
            if(i%5==1):
                commu.append(float(n[0]))
            elif(i%5==2):
                y.append(float(n[0]))
            elif(i%5==3):
                avow_commu.append(float(n[0]))
            elif(i%5==4):
                y2.append(float(n[0]))
            else:
                pass
            i+=1


            

x=[1,10,100,1000]

ind=range(1,len(x)+1)
#y=[14.85,13.822,14.811,14.007]

#y1=[0.119,0.146,0.485,3.591]
#y3=[416,416,416,416]
#y4=[192,480,3360,32160]
print(ind,y2,commu,avow_commu)

fig, ax1 = plt.subplots()

ax2 = ax1.twinx()
line1, = ax1.plot(ind,y,"bs-",label='Party Computation')
line2, =ax1.plot(ind, y2, 'b--o',label = 'Judge Computation')
line3, =ax2.plot(ind, log(commu), 'C1-.d',label="Party Comm")
line4, =ax2.plot(ind,log(avow_commu),"C1:*",label="Judge Comm")

ax1.plot(0,0)
ax1.plot(5,0)
ax1.set_xticklabels([0,0,1,10,100,1000])

ax1.set_xlabel("Number of Transcripts")
ax1.set_ylabel('Computation(ms)', color='black')
ax2.set_ylabel('Communication log(bytes)', color='red')
ax1.set_ylim(top=25,bottom=0)
ax2.set_ylim(top=15,bottom=0)
ax2.tick_params(axis='y', colors='red')
ax1.legend(handles=[line1, line2,line3,line4])
fig.savefig("image.png")

#plt.show()
#import tikzplotlibx
#tikzplotlib.save("avow-perf.tex")