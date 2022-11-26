lines = readlines("performance")
f=regexp(lines,'\d*','Match');

s=extract(lines(8),pat);
s1=extract(lines(13),pat);
s2=extract(lines(18),pat);
s3=extract(lines(23),pat);
y=[1000*str2double(s(1)+"."+s(2)),1000*str2double(s1(1)+"."+s1(2)),1000*str2double(s2(1)+"."+s2(2)),1000*str2double(s3(1)+"."+s3(2))]

s=extract(lines(10),pat);
s1=extract(lines(15),pat);
s2=extract(lines(20),pat);
s3=extract(lines(25),pat);
y1=[(str2double(s(1)+"."+s(2)))/1000, (str2double(s1(1)+"."+s1(2)))/1000, (str2double(s2(1)+"."+s2(2)))/1000 ,str2double(s3(1)+"."+s3(2))]


s=extract(lines(7),pat);
s1=extract(lines(12),pat);
s2=extract(lines(17),pat);
s3=extract(lines(22),pat);
y3=[str2double(s),str2double(s1),str2double(s2),str2double(s3)]


s=extract(lines(9),pat);
s1=extract(lines(14),pat);
s2=extract(lines(19),pat);
s3=extract(lines(24),pat);
y4=[str2double(s),str2double(s1),str2double(s2),str2double(s3)]




x=[1,10,100,1000];

ind=1:length(x);
%y=[14.85,13.822,14.811,14.907];

%y1=[0.119,0.146,0.485,3.591];
%y3=[416,416,416,416];
%y4=[192,480,3360,32160];
figure;

set(gca,'FontSize',18)


yyaxis left
plot(ind,y,"bs-",'DisplayName','Party Comptation');
hold on;
plot(ind,y1,"b--o",'DisplayName',"Judge Computation");

plot(0,0,'DisplayName','');


plot(5,0,'DisplayName','');

ylim([0,20]);
set(gca,'xtick',ind);
set(gca,'xticklabel',x);

ylabel("Computation(ms)");
yyaxis right;
plot(ind,log(y3),"-.d",'DisplayName',"Party Comm");
hold on;
plot(ind,log(y4),":*",'DisplayName',"Judge Comm");
hold on;
ylabel("Communication log(Bytes)");
ylim([0,15])

xlabel("Number of Transcripts");
legend('Party Comptation',"Judge Computation",'','',"Party Comm","Judge Comm");
ax = gca;
ax.YAxis(1).Color = 'k';
ax.YAxis(2).Color = 'r';