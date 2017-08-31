#!/usr/bin/python

'''
Issues:
	-Hover ToolTips?
	-Create logo
	-Scoll up when no scrollbar???
	-Go read PEP8
	-Properly rename all private methods
	-Create way for 'common' debugging from common methods
	-HTTP Except on no internet
	-Show debug queue length
	-Add window size to saved configuration
	-Overwrite thumbprnt always
	-Change HTTP scheme label when HTTPS selected
	-Detect and remove HTTP or HTTPS scheme in field
	-Run dubuggers in seperate PROCESS? (Performance)
	-Report HTTP error with background color?
	-Debug _config probes removed for recursion....why?
	-App startup too slow!!!!!

NEXT: Support for multiple config files

Debug Codes:
	1: Primary module outputs for regular module tshooting by users
	2: Method-level debugs (start and stop) for process tracing
	3: Intra-method debugs for troubleshooting within methods

Enhancements:
	-Build CLI outputer????
	-Support for multiple config files

-Build more modules:
	-RDP
	-ESP?
	-Traceroute? (ICMP, UDP?)
	-DNS
	-Custom TCP
	-Custom UDP
	-Captive Portal Detector
	-what is my public ip
	-IPv6 Checks
	-What is my IPv4
	-What is my IPv6
	-SIP (Aossey?)
	-LDAP
	-RADIUS
	-SQL
'''




# Set some global variables here
version = "0.1.0"
defaultconfigfile = "comchk.chk"
defaultconfigext = ".chk"




################ COMMON ######################
class common:
	module = "common"
	def stop(self):
		core.debug(self, 2, "common.stop: Unloading module")
	def start(self, checkconfig, guiobjs=False):
		core.debug(self, 2, "common.start called: Running startup procedure")
		core.debug(self, 3, "common.start: Starting with config:\n"+str(checkconfig))
		self.checkconfig = checkconfig
		self.guiobjs = guiobjs
		if guiobjs:
			core.debug(self, 3, "common.start: GUI detected, building GUI")
			self.guifields = {}
			self._build_gui()
			self.guiobjs["defaultmodule"].set(self.module)
			self.guiobjs["checkbutton"].config(command= lambda : self.run())
			core.debug(self, 3, "common.start: GUI Build Complete")
		core.debug(self, 3, "common.start: Loading startup config for module")
		self._load_config()
		core.debug(self, 3, "common.start: Config Load Complete")
	def run(self):
		core.debug(self, 2, "common.run called: Starting Check")
		if not self.running:
			core.debug(self, 3, "common.run: Starting Check Thread")
			self.thread = threading.Thread(target=self._check_worker)
			self.thread.daemon = True
			self.thread.start()
			self._running_status()
			core.debug(self, 3, "common.run: Completed")
		else:
			core.debug(self, 3, "common.run: Already Running, Aborting Thread Start")
	def _check_worker(self):
		core.debug(self, 2, "common._check_worker called: Beginning a check")
		core.debug(self, 3, "common._check_worker: Resetting status canvas")
		self.statuscanvas.itemconfig(self.status, fill='grey')
		self.statuscanvas.update()
		core.debug(self, 3, "common._check_worker: Calling common._assess to begin check")
		self._assess()
		core.debug(self, 3, "common._check_worker: Check completed")
	def _running_status(self):
		currentextent = -10
		arc = self.statuscanvas.create_arc(5, 5, 25, 25, width=4, outline="dim gray", fill="dim gray", start=90, extent=currentextent)
		self.running = True
		self.guiobjs["checkbutton"].config(state="disabled")
		while self.thread.is_alive():
			if currentextent > -360:
				currentextent -= 10
			else:
				currentextent = -50
			time.sleep(.05)
			self.statuscanvas.itemconfig(arc, extent=currentextent)
			self.statuscanvas.update()
		self.statuscanvas.delete(arc)
		self.statuscanvas.update()
		self.running = False
		self.guiobjs["checkbutton"].config(state="normal")
		return None
	def _config_changed(self, checkmethod=False, checkobjs=None):
		core.debug(self, 2, "common._config_changed called: Updating running config")
		core.update_config("merge", self._config())
		if checkmethod:
			core.debug(self, 3, "common._config_changed: Input check requested, calling %s" % str(checkmethod))
			checkmethod(checkobjs)
	def _load_config(self):
		core.debug(self, 2, "common._load_config called: Beginning load of configuration")
		debugging = "common._load_config: "
		for field in self.guifields:
			debugging += "\n-Trying field '%s'\n" % str(field)
			try:
				loadedvalue = self.checkconfig[field]
				if "PY_VAR" in self.guifields[field]._name:
					self.guifields[field].set(loadedvalue)
				elif self.guifields[field].winfo_class() == "Entry":
					currentstate = self.guifields[field].cget("state")
					self.guifields[field].config(state="normal")
					self.guifields[field].insert(tk.END, loadedvalue)
					self.guifields[field].config(state=currentstate)
				elif self.guifields[field].winfo_class() == "TCombobox":
					self.guifields[field].set(loadedvalue)
				elif self.guifields[field].winfo_class() == "Scale":
					self.guifields[field].set(loadedvalue)
				debugging += "--Success! Loaded with: '%s'\n" % str(loadedvalue)
			except KeyError:  # If config doesn't contain setting
				debugging +="--Field '%s' not found\n" % str(field)
		core.debug(self, 3, debugging)
		self._config_changed()
	def _config(self):
		config = {"id": self.checkconfig["id"], "module": self.module}
		for setting in self.guifields:
			config.update({setting: self.guifields[setting].get()})
		core.debug(self, 3, "common.config: Returning Config:\n%s" % str(config))
		return config
	def _set_status(self, color):
		colors = {
			"green": "lime green",
			"orange": "orange2",
			"red": "red"
		}
		color = colors[color]
		self.statuscanvas.itemconfig(self.status, fill=color)
		self.statuscanvas.update()




import re
# urlparse library for assess_url and split_url
try:
	# Python3 URL Libraries
	from urllib.parse import urlparse
except ImportError:
	# Python2 URL Libraries
	from urlparse import urlparse

class shared:
	module = "shared"
	#@@@@@@@@@@@@@@@@@@@@@ <GUI METHODS> @@@@@@@@@@@@@@@@@@@@@@
	###################### <GUI ELEMENTS> #####################
	def build_frame(self, parent, row, col, template="standard"):
		templates = {
			"standard": {},
			"setting": {"padx":5, "pady":5, "borderwidth":1, "relief":"sunken"}
		}
		template = templates[template]
		newframe = tk.Frame(parent, **template)
		newframe.grid(row=row, column=col, sticky="nesw")
		parent.grid_columnconfigure(col, weight=1)
		parent.grid_rowconfigure(row, weight=1)
		return newframe
	def build_label(self, parent, row, col, text):
		label = tk.Label(parent, text=text)
		label.grid(row=row, column=col)
		parent.grid_columnconfigure(col, weight=1)
		parent.grid_rowconfigure(row, weight=1)
		return label
	def build_entry(self, cobj, parent, row, col, template, chkmtd=None):
		templates = {
			"standard": {},
			"host": {"bd":1, "width":15}
		}
		template = templates[template]
		newvar = tk.StringVar()  # Use a StringVar so we can trace changes
		newentry = tk.Entry(parent, textvariable=newvar, **template)
		newentry.grid(row=row, column=col)
		parent.grid_columnconfigure(col, weight=1)
		parent.grid_rowconfigure(row, weight=1)
		if chkmtd:
			trace = lambda name, index, mode, newvar=newvar, newentry=newentry: cobj._config_changed(chkmtd, (newentry,))
		else:
			trace = lambda name, index, mode, newvar=newvar, newentry=newentry: cobj._config_changed()
		newvar.trace("w", trace)
		return (newentry, newvar)
	def build_scale(self, cobj, parent, row, col, intrange, length=100):
		frm = intrange[0]
		to = intrange[1]
		newscale = tk.Scale(parent, from_=frm, to=to, orient="horizontal", length=length, command= lambda x: cobj._config_changed())
		return newscale
	def build_button(self, parent, row, col, text, **kwargs):
		newint = tk.IntVar(value=0)
		newbutton = tk.Checkbutton(parent, text=text, variable=newint, **kwargs)
		newbutton.grid(row=row, column=col)
		parent.grid_columnconfigure(col, weight=1)
		parent.grid_rowconfigure(row, weight=1)
		return (newint, newbutton)
	def build_combobox(self, cobj, parent, row, col, vallist):
		newcombo = ttk.Combobox(parent, width=5, justify=tk.CENTER)
		newcombo['values'] = vallist
		newcombo.set(vallist[0])
		newcombo.state(['readonly'])
		newcombo.grid(row=row, column=col)
		newcombo.bind("<<ComboboxSelected>>", lambda evente:cobj._config_changed())
		return newcombo
	def build_radiobtns(self, cobj, parent, buttons):
		newvar = tk.IntVar(value=0)
		newvar.trace("w", lambda name, index, mode: cobj._config_changed())
		buttonlist = []
		for button in buttons:
			newbutton = tk.Radiobutton(parent, text=button["text"], variable=newvar, value=button["var"])
			newbutton.grid(row=button["row"], column=button["col"])
			buttonlist.append(newbutton)
		return (newvar, buttonlist)
	###################### </GUI ELEMENTS> #####################
	###################### <GUI TEMPLATES> #####################
	def build_host_field(self, cobj, parent, row, col):
		newframe = shared.build_frame(parent, row, col, "setting")
		newentry, newvar = shared.build_entry(cobj, newframe, 0, 0, "host", chkmtd=self.assess_host)
		label = shared.build_label(newframe, 1, 0, "Hostname or IP Address")
		return (newentry, newvar)
	def build_scale_field(self, cobj, parent, row, col, intrange, label, length=100):
		newframe = shared.build_frame(parent, row, col, "setting")
		newscale = shared.build_scale(cobj, newframe, 0, 0, intrange, length)
		newscale.grid(row=0, column=0)
		newscale.set(1)
		label = shared.build_label(newframe, 1, 0, label)
		return newscale
	def build_url_field(self, cobj, parent, row, col):
		newframe = shared.build_frame(parent, row, col, "setting")
		hostframe = shared.build_frame(newframe, 0, 0, "standard")
		newentry, newvar = shared.build_entry(cobj, hostframe, 0, 1, "host", chkmtd=self.assess_url)
		newentry.grid(sticky="w")
		httplabel = shared.build_label(hostframe, 0, 0, "http://")
		httplabel.grid(sticky="e")
		label = shared.build_label(newframe, 1, 0, "URL to Check")
		return (newentry, newvar)
	def build_button_and_entry(self, cobj, parent, row, col, text, chkmtd=None):
		newframe = shared.build_frame(parent, row, col, "setting")
		newbuttonvar, newbutton = shared.build_button(newframe, 0, 0, text, wraplength=100)
		newentry, newentryvar = shared.build_entry(cobj, newframe, 1, 0, "host", chkmtd=chkmtd)
		newentry.config(state="disabled", disabledbackground="grey")
		newbuttonvar.trace("w", lambda name, index, mode: cobj._config_changed(self.xable_object, (newbuttonvar, [newentry])))
		return (newbuttonvar, newentry)
	def build_button_and_combo(self, cobj, parent, row, col, text, drplist):
		newframe = shared.build_frame(parent, row, col, "setting")
		newbuttonvar, newbutton = shared.build_button(newframe, 0, 0, text, wraplength=100)
		newcombo = shared.build_combobox(cobj, newframe, 1, 0, drplist)
		newcombo.config(state="disabled")
		newbuttonvar.trace("w", lambda name, index, mode: cobj._config_changed(self.xable_object, (newbuttonvar, [newcombo])))
		return (newbuttonvar, newcombo)
	def build_status_frame(self, cobj, parent):
		newframe = tk.Frame(parent, borderwidth=1, relief=tk.SUNKEN)
		newframe.grid(row=0, column=100, sticky="nesw")
		newframe.grid_rowconfigure(0, weight=1)
		newcanvas = tk.Canvas(newframe, width=25, height=25)
		newcanvas.grid(row=0, column=0)
		newstatus = newcanvas.create_oval(5, 5, 25, 25, width=1, fill='grey')
		return (newcanvas, newstatus)
	###################### </GUI TEMPLATES> #####################
	#@@@@@@@@@@@@@@@@@@@@@ </GUI METHODS> @@@@@@@@@@@@@@@@@@@@@@@
	#@@@@@@@@@@@@@@@@@@@@@ <INPUT CHECKS> @@@@@@@@@@@@@@@@@@@@@@@
	################## <ELEMENTAL INPUT CHECKS> #################
	def check_domainname(self, domainname):
		result = {"status": "pass", "messages": []} # Start with a passing result
		##### 1. Check that only legal characters are in name (RFC883 and RFC952) #####
		characterregex = "^[a-zA-Z0-9\-\.]+$" # A list of the valid domain-name characters in a domain name
		charactercheck = "fail" # Begin with a failing result
		for entry in re.findall(characterregex, domainname): # For each string in the list returned by re.findall
			if entry == domainname: # If one of the strings in the returned list equals the full domainname string
				charactercheck = "pass" # Then all its characters are legal and it passes the check
				result["messages"].append({"OK": "No illegal characters found"}) # Append a message to the result
		if charactercheck == "fail": # If the check failed
			result["messages"].append({"FATAL": "Illegal character found. Only a-z, A-Z, 0-9, period (.), and hyphen (-) allowed."})
		##### 2. Check the Length Restrictions: 63 max char per label, 253 max total (RFC1035) #####
		if len(domainname) <= 253: # If total length of domain name is 253 char or less
			result["messages"].append({"OK": "Domain total length is good"})
			labelcheck = {'passlength': 0, 'faillength': 0} # Start a tally of passed and failed labels
			for label in domainname.split("."): # Split the domain into its labels and for each label
				if len(label) <= 63: # If the individual label is less than or equal to 63 characters...
					labelcheck['passlength'] = labelcheck['passlength'] + 1 # Add it as a passed label in the tally
				else: # If it is longer than 63 characters
					labelcheck['faillength'] = labelcheck['faillength'] + 1 # Add it as a failed label in the tally
					result["messages"].append({"FATAL": "Label: " + label + " exceeds max label length of 63 characters"})
			if labelcheck['faillength'] == 0: # If there are NOT any failed labels in the tally
				maxlengthcheck = "pass" # Then all labels are passed and the check passes
		##### 3. Check that first and last character are not a hyphen or period #####
		firstcharregex = "^[a-zA-Z0-9]" # Match a first character of upper or lower A-Z and any digit (no hyphens or periods)
		lastcharregex = "[a-zA-Z0-9]$" # Match a last character of upper or lower A-Z and any digit (no hyphens or periods)
		if len(re.findall(firstcharregex, domainname)) > 0: # If the first characters produces a match
			result["messages"].append({"OK": "Domain first character is legal"})
			if len(re.findall(lastcharregex, domainname)) > 0: # And the last characters produces a match
				result["messages"].append({"OK": "Domain last character is legal"})
				firstlastcheck = "pass" # Then first and last characters are legal and the check passes
			else:
				result["messages"].append({"FATAL": "First and last character in domain must be alphanumeric"})
		else:
			result["messages"].append({"FATAL": "First and last character in domain must be alphanumeric"})
		##### 4. Check that no labels begin or end with hyphens (https://www.icann.org/news/announcement-2000-01-07-en) #####
		beginendhyphenregex = "\.\-|\-\." # Match any instance where a hyphen follows a period or vice-versa
		if len(re.findall(beginendhyphenregex, domainname)) == 0: # If the regex does NOT make a match anywhere
			result["messages"].append({"OK": "No labels begin or end with hyphens"})
			beginendhyphencheck = "pass" # Then no names begin with a hyphen and the check passes
		else:
			result["messages"].append({"FATAL": "Each label in the domain name must begin and end with an alphanumeric character. No hyphens"})
		##### 5. No double periods or triple-hyphens exist (RFC5891 for double-hyphens) #####
		nomultiplesregex = "\.\.|\-\-\-" # Match any instance where a double period (..) or a triple hyphen (---) exist
		if len(re.findall(nomultiplesregex, domainname)) == 0: # If the regex does NOT make a match anywhere
			result["messages"].append({"OK": "No double periods or triple hyphens found"})
			nomultiplescheck = "pass" # Then no double periods or triple hyphens exist and the check passes
		else:
			result["messages"].append({"FATAL": "No double-periods (..) or triple-hyphens (---) allowed in domain name"})
		##### 6. There is at least one period in the domain name #####
		periodinnameregex = "\." # Match any instance of a period
		if len(re.findall(periodinnameregex, domainname)) > 0: # If there is at least one period in the domain name...
			periodinnamecheck = "pass"
			result["messages"].append({"OK": "At least one period found in the domain name"})
		else:
			result["messages"].append({"WARNING": "No period (.) found in domain name. FQDNs are preferred but not required."})
		##### Make sure all checks are passed #####
		for listentry in result["messages"]:
			for key in listentry:
				if key == "FATAL":
					result["status"] = "fail"
		return result
	def check_ipv4(self, iptype, ipdata):
		result = {"status": "", "messages": []} # Initialize result
		if iptype == "address":
			ipregex = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
			result["messages"].append({"OK": "IP parsed as type: Address"})
		elif iptype == "cidr":
			ipregex = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|1[0-9]|2[0-9]|3[0-2]?)$"
			result["messages"].append({"OK": "IP parsed as type: CIDR"})
		check = re.search(ipregex, ipdata)
		if check is None:
			result["status"] = "fail"
			result["messages"].append({"FATAL": "Address failed parsing"})
		else:
			result["status"] = "pass"
			result["messages"].append({"OK": "Address passed parsing"})
		return result
	################## </ELEMENTAL INPUT CHECKS> ################
	################## <FIELD INPUT CHECKS> #####################
	def assess_host(self, args):
		entryobject = args[0]
		inputstring = entryobject.get()
		domainbad = False
		ipv4bad = False
		if shared.check_domainname(inputstring)["status"] != "pass":
			domainbad = True
		if shared.check_ipv4("address", inputstring)["status"] != "pass":
			ipv4bad = True
		if domainbad and ipv4bad:
			entryobject.config(foreground="red")
		else:
			entryobject.config(foreground="black")
	def assess_regex(self, args):
		entryobject = args[0]
		try:
			regex = entryobject.get()
			re.findall(regex, "")
			entryobject.config(foreground="black")
		except:
			entryobject.config(foreground="red")
	def xable_object(self, args):
		checkbuttonvar = args[0]
		destobjectlist = args[1]
		for destobject in destobjectlist:
			if checkbuttonvar.get() == 1:
				destobject.config(state="normal")
			else:
				destobject.config(state="disabled")
	def assess_url(self, args):
		entryobject = args[0]
		url = entryobject.get()
		if "//" not in url:
			url = "http://"+url
		parsed = urlparse(url)
		if parsed.hostname == None:
			entryobject.config(foreground="red")
		else:
			if shared.check_domainname(parsed.hostname)["status"] == "pass":
				entryobject.config(foreground="black")
			else:
				entryobject.config(foreground="red")
	################## </FIELD INPUT CHECKS> ####################
	#@@@@@@@@@@@@@@@@@@@@@ </INPUT CHECKS> @@@@@@@@@@@@@@@@@@@@@@
	#@@@@@@@@@@@@@@@@@@@<MISC SHARED METHODS> @@@@@@@@@@@@@@@@@@@
	def console(self, data):
		print(data)
	def detect_os(self):
		import platform
		global windows, linux, macos
		windows=True if platform.system().lower()=="windows" else False
		linux=True if platform.system().lower()=="linux" else False
		macos=True if platform.system().lower()=="darwin" else False
	def runcommand(self, command):
		import subprocess
		try:
			return (0,subprocess.check_output(command, shell=True).decode("utf-8"))
		except subprocess.CalledProcessError as exception:
			return (exception.returncode, exception.output.decode("utf-8"))
	def split_url(self, url):
		if "//" not in url:
			url = "http://"+url
		parseresult = urlparse(url) # Get the ParseResult class
		ordered_dict = parseresult._asdict() # Get the OrderedDict class
		regular_dict = dict(ordered_dict) # Get a regular dictionary of components
		if regular_dict["netloc"] == None: # If parsing failed
			return False
		return regular_dict
	#@@@@@@@@@@@@@@@@@@@</MISC SHARED METHODS> @@@@@@@@@@@@@@@@@@@




###################################################################
######################### <CHECK MODULES> #########################
###################################################################
################## PING ######################
import re
import threading
class ping(common):
	module = "ping"
	running = False
	def _ping(self, host, count=1, timeout=1, worker=False, result={}):
		if worker:
			if windows:
				command = "ping -n %s -w %s %s" % (count, timeout, host)
			else:
				command = "ping -c %s -W %s %s" % (count, timeout, host)
			self.pingdebugs += "     Calling 'shared.runcommand' with command: '%s'\n" % command
			result.update({threading.currentThread().getName(): shared.runcommand(command)})
		else:
			self.pingdebugs = "ping._ping: Worker thread debugs:\n"
			core.debug(self, 2, "ping._ping called: Starting Ping with settings:\n\
			host: %s\n\
			count: %s\n\
			timeout: %s" % (host, count, timeout))
			result = {}
			for each in range(count):
				thread = threading.Thread(target=self._ping, args=(host,1,timeout,True,result))
				thread.start()
			while len(result) != count:
				pass
			core.debug(self, 3, self.pingdebugs)
			del self.pingdebugs
			core.debug(self, 3, "ping._ping: All threads finished. Returning results")
			return result
	def _check_timeout(self, threads):
		core.debug(self, 2, "ping._check_timeout called: Getting timeout stats")
		times = []
		goodtime = 0
		maximum = 0
		minimum = 1000000
		baseline = int(self.guifields["timeout"].get())
		if windows:
			regex = "[0-9]+ms"
		else:
			regex = "stddev = [0-9]+"
		for thread in threads:
			ms = int(re.findall("[0-9]+", re.findall(regex, threads[thread][1])[0])[0])
			times.append(ms)
			if ms <= baseline:
				goodtime += 1
			if ms > maximum:
				maximum = ms
			if ms < minimum:
				minimum = ms
		average = sum(times)/len(times)
		stats = "ping._check_timeout: Ping Statistics:\n"
		stats += "     Minimum: %sms\n" % minimum
		stats += "     Maximum: %sms\n" % maximum
		stats += "     Average: %sms" % average
		core.debug(self, 1, stats)
		return {"goodtime": goodtime, "times": times}
	def _assess(self):
		core.debug(self, 2, "ping._assess called: Beginning a check...")
		host = self.guifields["host"].get()
		count = int(self.guifields["repeat"].get())
		pingdata = self._ping(host, count=count)
		successes = 0
		goodtime = 0
		for thread in pingdata:
			if pingdata[thread][0] == 0:
				successes += 1
		core.debug(self, 1, "ping._assess: Successful pings: %s/%s" % (str(len(pingdata)), str(successes)))
		if successes > 0:
			timeouts = self._check_timeout(pingdata)
			goodtime = timeouts["goodtime"]
			core.debug(self, 1, "ping._assess: Pings within timeout threshold: %s/%s" % (str(goodtime), str(len(pingdata))))
			if goodtime < len(pingdata):
				core.debug(self, 3, "ping._assess: Returned pings outside of threshold, setting status")
				self._set_status("orange")
			else:
				core.debug(self, 3, "ping._assess: Returned pings good, setting status")
				self._set_status("green")
		else:
			core.debug(self, 3, "ping._assess: No returned pings, setting status")
			self._set_status("red")
	def _build_gui(self):
		core.debug(self, 2, "ping._build_gui called: Starting GUI Build")
		###########################
		baseframe = shared.build_frame(self.guiobjs["checkframe"], 0, 0)
		###########################
		hostentry, hostvar = shared.build_host_field(self, baseframe, 0, 0)
		self.guifields.update({'host': hostentry})
		###########################
		repeatscale = shared.build_scale_field(self, baseframe, 0, 1, (1, 100), "Ping Count")
		self.guifields.update({'repeat': repeatscale})
		###########################
		timeoutscale = shared.build_scale_field(self, baseframe, 0, 2, (1, 2000), "Timeout (ms)", 300)
		self.guifields.update({'timeout': timeoutscale})
		###########################
		self.statuscanvas, self.status = shared.build_status_frame(self, baseframe)
		###########################
		core.debug(self, 3, "ping._build_gui: GUI build complete")




################ HTTP ######################
import re
import ssl
import hashlib
import multiprocessing
try:
	# Python3 URL Libraries
	from urllib.request import urlopen
	from urllib.request import URLError
	from urllib.request import build_opener
	from urllib.request import HTTPSHandler
	from urllib.parse import urlparse
except ImportError:
	# Python2 URL Libraries
	from urllib2 import urlopen
	from urllib2 import URLError
	from urllib2 import build_opener
	from urllib2 import HTTPSHandler
	from urlparse import urlparse

class http(common):
	module = "http"
	maxbodylength = 1000
	running = False
	def _http_get(self, host):
		core.debug(self, 2, "http._http_get called: Getting URL: %s" % str(host))
		if self.guifields["checkssl"].get() == 1:
			scheme = "https://"
		else:
			scheme = "http://"
		opener = self._opener()
		try:
			response = opener.open(scheme+host)
		except (URLError, ssl.CertificateError) as error:
			core.debug(self, 1, "http._http_get: HTTP Error: %s" % str(error))
			return error
		code = response.getcode()
		headers = response.headers.values()
		core.debug(self, 1, "http._http_get: Returned HTTP Code: %s" % str(code))
		core.debug(self, 1, "http._http_get: Returned HTTP Headers: %s" % str(headers))
		body = response.read()
		body = self._decode(headers, body)
		core.debug(self, 1, "http._http_get: HTTP Body Length is %s" % str(len(body)))
		if len(body) > self.maxbodylength:
			core.debug(self, 1, "http._http_get: Jumbo HTTP Body. Max length is %s. Use Debug Level 3 to see HTTP Body" % str(self.maxbodylength))
			core.debug(self, 3, "http._http_get: Returned Jumbo HTTP Body: %s" % str(body))
		else:
			core.debug(self, 1, "http._http_get: Returned HTTP Body: %s" % str(body))
		return {"code": code, "headers": headers, "body": body}
	def _opener(self):
		core.debug(self, 2, "http._opener called: Checking SSL to Build Opener")
		if self.guifields["checkssl"].get() == 1:
			hostname = shared.split_url(self.guifields["host"].get())["netloc"]
			#pem = ssl.get_server_certificate((hostname, 443))
			try:
				pem = ssl.get_server_certificate((hostname, 443))
				core.debug(self, 1, "http._opener: SSL Certificate (PEM):\n"+pem)
				self.hashes = self._ssl_fingerprnt(pem)
				self._update_hash(self.hashes["sha256"])
			except:
				core.debug(self, 2, "http._opener called: SSL Retrieval Error")
			context = ssl.create_default_context()
			if self.guifields["sslsource"].get() == 2:
				core.debug(self, 1, "http._opener: Performing SSL Certificate Validation Against Trusted CAs")
			else:
				if self.guifields["sslsource"].get() == 0:
					core.debug(self, 1, "http._opener: Ignoring SSL Certificate Validation")
				elif self.guifields["sslsource"].get() == 1:
					core.debug(self, 1, "http._opener: _assess will check SSL fingerprnt")
				context.check_hostname = False
				context.verify_mode = ssl.CERT_NONE
			opener = build_opener(HTTPSHandler(context=context))
			opener.addheaders = []
			return opener
		else:
			opener = build_opener()
			opener.addheaders = []
			return opener
	def _ssl_fingerprnt(self, pem):
		core.debug(self, 2, "http._ssl_fingerprnt called: Getting SSL Certificate Fingerprnts")
		debugging = "Certificate Fingerprnts: \n"
		der = ssl.PEM_cert_to_DER_cert(pem)
		results = {
			"md5": hashlib.md5(),
			"sha1": hashlib.sha1(),
			"sha256": hashlib.sha256()
		}
		for hsh in results:
			results[hsh].update(der)
			results[hsh] = results[hsh].hexdigest()
			debugging += "      %s: %s\n" % (hsh, results[hsh])
		core.debug(self, 1, debugging)
		return results
	def _update_hash(self, hashdata):
		core.debug(self, 2, "http._update_hash called: Checking to update hash field")
		if self.guifields["sslsource"].get() == 0 or self.guifields["sslsource"].get() == 2:
			if self.guifields["hash"].get() == "":
				core.debug(self, 2, "http._update_hash: Updating hash field with SHA256 hash for convenience")
				self.guifields["hash"].set(hashdata)
	def _decode(self, headers, body):
		core.debug(self, 2, "http._decode called: Trying to decode body with header charset")
		for header in headers:
			if "charset=" in header:
				core.debug(self, 3, "http._decode: Charset found in header")
				charset = re.findall("=.*", header)[0]
				charset = charset[1:]
				core.debug(self, 3, "http._decode: Decoding charset set as "+charset)
				break
			else:
				charset = "utf8"
		try:
			core.debug(self, 3, "http._decode: Attempting decode of HTTP body using charset")
			return body.decode(charset).encode('utf8')
		except UnicodeDecodeError as error:
			core.debug(self, 3, "http._decode: Decoding Error: "+ str(error))
			core.debug(self, 3, "http._decode: Sending body to shared.console due to decoding error")
			shared.console(body)
	def _check_errors(self, response):
		if type(response) == type({}):
			return (True,)
		else:
			return (False,)
	def _search(self, response):
		core.debug(self, 2, "http._search called: Beginning regex search")
		result = {}
		regex = self.guifields["pattern"].get()
		core.debug(self, 3, "http._search: Loaded Regex Pattern: "+regex)
		body = response["body"]
		foundlist = re.findall(regex, str(body))
		core.debug(self, 1, "http:_search: List of found values: "+ str(foundlist))
		if len(foundlist) > 0:
			core.debug(self, 1, "http:_search: Regex pattern found, returning data")
			result.update({"matched": True, "returned": foundlist[0]})
		else:
			core.debug(self, 1, "http:_search: Regex pattern not found")
			result.update({"matched": False})
		return result
	def _check_code(self, response):
		code = response["code"]
		if code == int(self.guifields["code"].get()):
			return True
		else:
			return False
	def _assess(self):
		core.debug(self, 2, "http._assess called: Beginning a HTTP check")
		host = self.guifields["host"].get()
		pattern = self.guifields["pattern"].get()
		response = self._http_get(host)
		results = []
		# Catch HTTP errors and kill _assess
		if not self._check_errors(response)[0]:
			core.debug(self, 1, "http._assess: Fault returned from http._http_get")
			self._set_status("red")
			return None
		# Check Regex pattern
		if self.guifields["checkpattern"].get() == 1:
			searched = self._search(response)
			core.debug(self, 3, "http._assess: Search of body returned: "+str(searched))
			if searched["matched"] == True:
				results.append(True)
			else:
				results.append(False)
		# Check Response code
		if self.guifields["checkcode"].get() == 1:
			if self._check_code(response):
				results.append(True)
			else:
				results.append(False)
		# Check SSL Fingerprnts
		if self.guifields["sslsource"].get() == 1 and self.guifields["checkssl"].get() == 1:
			core.debug(self, 2, "http._assess: Checking SSL Certificate Fingerprnt")
			hashlist = list(self.hashes.values())
			if self.guifields["hash"].get().lower() in hashlist:
				core.debug(self, 1, "http._assess: Fingerprnt matches")
				results.append(True)
			else:
				core.debug(self, 1, "http._assess: Fingerprnt does not match")
				results.append(False)
		#######################
		# Check results
		if False in results:
			core.debug(self, 1, "http._assess: Some checks failed in http, Setting status")
			self._set_status("red")
		else:
			core.debug(self, 1, "http._assess: Successful Check, Setting status")
			self._set_status("green")
	def _build_gui(self):
		core.debug(self, 2, "http._build_gui called: Starting GUI Build")
		###########################
		baseframe = shared.build_frame(self.guiobjs["checkframe"], 0, 0)
		###########################
		hostentry, hostvar = shared.build_url_field(self, baseframe, 0, 0)
		self.guifields.update({'host': hostentry})
		###########################
		checkpatternvar, pattenentry = shared.build_button_and_entry(self, baseframe, 0, 1, "Check Body for Pattern (Regex)", chkmtd=shared.assess_regex)
		self.guifields.update({'pattern': pattenentry})
		self.guifields.update({'checkpattern': checkpatternvar})
		###########################
		checkcodevar, codemenu = shared.build_button_and_combo(self, baseframe, 0, 2, "Check Response Code", [200,301])
		self.guifields.update({'checkcode': checkcodevar})
		self.guifields.update({'code': codemenu})
		###########################
		# A custom setting frame (ssl settings) using elements instead of templates
		sslframe = shared.build_frame(baseframe, 0, 3, template="setting")
		checksslvar, checkssl = shared.build_button(sslframe, 0, 0, "Use HTTPS")
		checkssl.grid(columnspan=2)
		self.guifields.update({'checkssl': checksslvar})
		buttons = [
			{"var": 0, "text": "No SSL Verification", "row": 1, "col": 0},
			{"var": 1, "text": "Use Cert Fingerprint", "row": 1, "col": 1},
			{"var": 2, "text": "Use Local CA Store", "row": 2, "col": 0}
		]
		sslbuttons = shared.build_radiobtns(self, sslframe, buttons)
		checksslsourcevar = sslbuttons[0]
		checksslsourcenone, checksslsourcehash, checksslsourcelocal = sslbuttons[1]
		self.guifields.update({'sslsource': checksslsourcevar})
		checksslvar.trace("w", lambda name, index, mode: self._config_changed(shared.xable_object, (checksslvar, [checksslsourcenone, checksslsourcehash, checksslsourcelocal])))
		checksslvar.set(0)
		hashentry, hashvar = shared.build_entry(self, sslframe, 2, 1, "host", chkmtd=None)
		hashentry.config(state="disabled", disabledbackground="grey")
		checksslsourcevar.trace("w", lambda name, index, mode: self._config_changed(shared.xable_object, (checksslsourcevar, [hashentry])))
		self.guifields.update({'hash': hashvar})
		###########################
		self.statuscanvas, self.status = shared.build_status_frame(self, baseframe)
		###########################
		core.debug(self, 3, "http._build_gui: GUI build complete")




################ DEBUG ######################
import sys
import time
try:
	import Queue # Import Python2 queue library
except ImportError:
	import queue as Queue # Import Python3 queue library

class debug:
	module = "debug"
	def _debug(self, obj, level, text):
		# No debug probe here to prevent recursion
		moduledebuglevel = self._config()["modules"][obj.module]["level"]
		if level <= moduledebuglevel:
			self._write_output("["+str(level)+"] "+str(text), obj.module)
	def _create_option(self, modulename, column):
		core.debug(self, 2, "debug._create_option called: Creating module '%s' options" % modulename)
		frame = tk.Frame(self.optionsframe, padx=25, pady=5, borderwidth=1, relief=tk.SUNKEN)
		frame.grid(row=0, column=column, sticky="nesw")
		frame.grid_rowconfigure(1, weight=1)
		color = next(self.defaultcolor)
		newlabel = tk.Label(frame, text=modulename, fg=color)
		newlabel.grid(row=1, column=0)
		newlabel.bind("<Button-1>", lambda e:self._pick_color(modulename, newlabel))
		self.textbox.tag_config(modulename, foreground=color)
		levelscale = tk.Scale(frame, from_=3, to=0, orient=tk.VERTICAL, command= lambda x: self._config_changed())
		levelscale.config(length=50, sliderlength=20)
		levelscale.grid(row=2, column=0)
		levelscale.set(0)
		return {modulename: {
			"frame": frame,
			"label": newlabel,
			"scale": levelscale
			}}
	def _write_output(self, text, module):
		# No debug probe here to prevent recursion
		self.textbox.config(state=tk.NORMAL)
		start = str(float(self.textbox.index("end")) + 0.4)
		self.textbox.insert("end", "\n"+text)
		self.textbox.insert("end", ("\n"+"#"*50))
		end = str(float(self.textbox.index("end")) - 1)
		self.textbox.config(state=tk.DISABLED)
		self.textbox.see("end")
		self.textbox.tag_add(module, start, end)
	def _clear_buffer(self):
		core.debug(self, 2, "debug._clear_buffer called: Clearing debug buffer")
		self.textbox.config(state=tk.NORMAL)
		self.textbox.delete(1.0, "end")
		self.textbox.config(state=tk.DISABLED)
		self.textbox.see("end")
	def _default_color(self):
		core.debug(self, 2, "debug._default_color called: Instantiating generator")
		colorlist = ["#ff0000", "#996633", "#000000", "#0000ff", "#ff00ff"]
		index = 0
		while True:
			core.debug(self, 3, "debug._default_color: Yielding color '%s'" % colorlist[index])
			yield colorlist[index]
			if index == len(colorlist) - 1:
				index = 0
			else:
				index += 1
	def _pick_color(self, module, labelobj):
		core.debug(self, 2, "debug._pick_color called: Running askcolor()")
		color = askcolor()[1]
		core.debug(self, 3, "debug._pick_color: Returning color '%s'" % color)
		labelobj.config(fg=color)
		self.textbox.tag_config(module, foreground=color)
		self._config_changed()
	def _copy_to_clipboard(self):
		core.debug(self, 2, "debug._copy_to_clipboard called: Copying buffer to clipboard")
		core.root.clipboard_clear()
		core.root.clipboard_append(self.textbox.get(1.0, tk.END))
	def _wrap_text(self):
		core.debug(self, 2, "debug._wrap_text called: Check buffer text wrapping")
		if self.wrapvar.get() == 1:
			core.debug(self, 3, "debug._wrap_text: Setting word-level wrapping")
			self.textbox.config(wrap="word")
		else:
			core.debug(self, 3, "debug._wrap_text: Removing wrapping")
			self.textbox.config(wrap="none")
		self._config_changed()
	def _worker(self):
		# No debug probe here to prevent recursion
		while True:
			if self.kill:
				quit()
			else:
				if self.queue.empty():
					time.sleep(.1)
				else:
					data = self.queue.get()
					self._debug(data[0], data[1], data[2])
					self.queue.task_done()
	def start(self, checkconfig, guiobjs=False):
		core.debug(self, 2, "debug.start called: Running startup procedure")
		self.kill = False
		self.checkconfig = checkconfig
		self.guiobjs = guiobjs
		if guiobjs:
			core.debug(self, 3, "debug.start: GUI detected, building GUI")
			self._build_gui()
			core.debug(self, 3, "debug.start: GUI Build Complete")
		core.debug(self, 3, "debug.start: Loading startup config for module")
		self._load_config()
		core.debug(self, 3, "debug.start: Creating debug queue")
		self.queue = Queue.Queue(maxsize=0)
		core.debuggers.update({self.checkconfig["id"]:self.queue})
		core.debug(self, 3, "debug.start: Creating debug thread")
		self.thread = threading.Thread(target=self._worker)
		self.thread.daemon = True
		core.debug(self, 3, "debug.start: Starting debug thread")
		self.thread.start()
		core.debug(self, 2, "debug.start: Startup procedure complete")
		###############################
	def stop(self):
		del core.debuggers[self.checkconfig["id"]]
		self.kill = True
	def _build_gui(self):
		core.debug(self, 2, "debug._build_gui called: Starting GUI Build")
		self.guifields = {}
		self.defaultcolor = self._default_color()
		self.guiobjs["defaultmodule"].set(self.module)
		baseframe = tk.Frame(self.guiobjs["checkframe"])
		baseframe.grid(row=0, column=0, sticky="nesw")
		baseframe.grid_columnconfigure(0, weight=1)
		baseframe.grid_rowconfigure(1, weight=1)
		###########################
		self.optionsframe = tk.Frame(baseframe, padx=5, pady=5, borderwidth=1, relief=tk.SUNKEN)
		self.optionsframe.grid(row=0, column=0, sticky="nesw")
		self.options = {}
		###########################
		clearframe = tk.Frame(self.optionsframe, padx=25, pady=5, borderwidth=1, relief=tk.SUNKEN)
		clearframe.grid(row=0, column=0, sticky="nesw")
		clearframe.grid_rowconfigure(1, weight=1)
		copybutton = tk.Button(clearframe, text="Copy All", command= lambda: self._copy_to_clipboard())
		copybutton.grid(row=0, column=0)
		clearbutton = tk.Button(clearframe, text="Clear Buffer", command= lambda: self._clear_buffer())
		clearbutton.grid(row=1, column=0)
		self.wrapvar = tk.IntVar(value=1)
		wrapbox = tk.Checkbutton(clearframe, text="Wrap Text", variable=self.wrapvar, command= lambda: self._wrap_text())
		wrapbox.grid(row=2, column=0)
		###########################
		textboxframe = tk.Frame(baseframe, borderwidth=4, relief=tk.RAISED)
		textboxframe.grid(row=1, column=0, columnspan=101, sticky=tk.N+tk.S+tk.W+tk.E)
		textboxframe.grid_columnconfigure(0, weight=1)
		textboxframe.grid_rowconfigure(0, weight=1)
		scrollbary = tk.Scrollbar(textboxframe)
		scrollbarx = tk.Scrollbar(textboxframe, orient=tk.HORIZONTAL)
		self.textbox = tk.Text(textboxframe, height=20, width=75, bg="white smoke", yscrollcommand=scrollbary.set, xscrollcommand=scrollbarx.set)
		self.textbox.bind("<1>", lambda event: self.textbox.focus_set())
		self.textbox.config(highlightthickness=0)
		scrollbary.config(command=self.textbox.yview)
		scrollbarx.config(command=self.textbox.xview)
		self.textbox.grid(row=0, column=0, sticky=tk.N+tk.S+tk.W+tk.E)
		scrollbary.grid(row=0, column=1,sticky=tk.N+tk.S+tk.W+tk.E)
		scrollbarx.grid(row=1, column=0,sticky=tk.N+tk.S+tk.W+tk.E)
		self.textbox.insert("end", "\nDebugging data will be listed here\n")
		self.textbox.insert("end", ("\n"+"#"*50))
		self.textbox.config(state=tk.DISABLED)
		self.textbox.see("end")
		###########################
		newoption = self._create_option("core", 1)
		self.options.update(newoption)
		newoption = self._create_option("gui", 2)
		self.options.update(newoption)
		newoption = self._create_option("shared", 3)
		self.options.update(newoption)
		column = 4
		for module in core.resources:
			newoption = self._create_option(module, column)
			self.options.update(newoption)
			column += 1
		###########################
		self.guiobjs["checkbutton"].config(command= lambda : self.run())
		core.debug(self, 3, "debug._build_gui: GUI build complete")
	def _load_config(self):
		core.debug(self, 2, "debug._load_config called: Beginning load of configuration")
		try:
			self.wrapvar.set(self.checkconfig["linewrap"])
			for module in self.options:
				level = self.checkconfig["modules"][module]["level"]
				color = self.checkconfig["modules"][module]["color"]
				self.options[module]["scale"].set(level)
				self.options[module]["label"].config(fg=color)
				self.textbox.tag_config(module, foreground=color)
		except KeyError:  # If config doesn't contain setting
			pass
		self._config_changed()
	def run(self):
		core.debug(self, 2, "debug.run called: Nothing to do")
		pass
	def _config(self):
		# No debug probes here to prevent recursion
		#core.debug(self, 2, "debug._config called: Generating debug config")
		checkid = self.checkconfig["id"]
		wrap = self.wrapvar.get()
		optiondict = {"id": checkid, "module": self.module, "linewrap": wrap, "modules": {}}
		for option in self.options:
			level = self.options[option]["scale"].get()
			color = self.options[option]["label"].config()['foreground'][4]
			optiondict["modules"].update({option: {"level": level, "color": color}})
			#core.debug(self, 3, "debug.config: Returning Config:\n%s" % str(optiondict))
		return optiondict
	def _config_changed(self, includecheck=False, entryobj=None, varobj=None):
		core.debug(self, 3, "debug._config_changed called: Updating running config")
		config = self._config()
		core.debug(self, 3, "New Config: "+str(config))
		core.update_config("merge", self._config())
###################################################################
######################### </CHECK MODULES> ########################
###################################################################




###################################################################
######################### <CORE CLASSES> ##########################
###################################################################

################## GUI ######################
import sys
import webbrowser

try:
	# Python3 GUI Libraries
	import tkinter as tk
	from tkinter.colorchooser import askcolor  # For debug module
	gui_ready = True
except ImportError:
	# Python2 GUI Libraries
	try:
		import Tkinter as tk
		from tkColorChooser import askcolor   # For debug module
		gui_ready = True
	except ImportError:
		gui_ready = False

# Import ttk seperately due to unique OS X paths
try:
	from tkinter import ttk
except ImportError:
	try:
		import ttk
	except ImportError:
		pass


class gui:
	module = "gui"
	def __init__(self, master):
		self.master = master
		master.title("ComCheck")
		master.geometry('1080x700')
		#master.attributes('-alpha', .80) # Transparency
		master.grid_columnconfigure(0, weight=1)
		master.grid_rowconfigure(1, weight=1)
		logo = tk.PhotoImage(data=logoimagedata)
		master.tk.call('wm','iconphoto',master._w,logo)
		#####################
		checkbuttonframe = tk.Frame(master)
		checkbuttonframe.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
		checkbuttonframe.grid_columnconfigure(1, weight=1)
		self.newcheckbuttonimage = tk.PhotoImage(data=newcheckimagedata)
		newcheckbutton = tk.Button(checkbuttonframe, image=self.newcheckbuttonimage, text='+', command=self.create_check)
		newcheckbutton.grid(row=0, column=0, sticky="nw")
		checkallframe = tk.Frame(checkbuttonframe)
		checkallframe.grid(row=0, column=1, padx=87, sticky="nw")
		self.runallbuttonimage = tk.PhotoImage(data=runallimagedata)
		checkallbutton = tk.Button(checkallframe, image=self.runallbuttonimage, command= lambda: core.run_all())
		checkallbutton.grid(row=0, column=0)
		self.configentry = ttk.Combobox(checkbuttonframe, width=25, justify=tk.CENTER)
		self.configentry.grid(row=0, column=2, sticky="e")
		self.configentry.bind("<<ComboboxSelected>>", lambda evente:self._config_file_populate(self.configentry))
		self.savebuttonimage = tk.PhotoImage(data=saveimagedata)
		savebutton = tk.Button(checkbuttonframe, image=self.savebuttonimage, command= lambda: core.save_config())
		savebutton.grid(row=0, column=3, sticky="e")
		#####################
		canvasframe = tk.Frame(master)
		canvasframe.grid(row=1, column=0, sticky="nesw")
		#####################
		self.bwcanvas = tk.Canvas(canvasframe, highlightthickness=0)
		self.bwcanvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
		self.bw = tk.Frame(self.bwcanvas)
		self.bw.grid_columnconfigure(0, weight=1)
		self.bw.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
		bwscroll = tk.Scrollbar(canvasframe)
		bwscroll.pack(side=tk.RIGHT, fill='y')
		self.bwcanvas.configure(yscrollcommand = bwscroll.set)
		bwscroll.config(command=self.bwcanvas.yview)
		interior_id = self.bwcanvas.create_window(0, 0, window=self.bw, anchor=tk.N+tk.W)
		self.bwcanvas.bind('<Configure>', lambda event, a=self.bwcanvas, b=interior_id:self._on_configure(event, a, b))
		self.bwcanvas.bind_all("<MouseWheel>", self._on_mousewheel)
		self.bwcanvas.configure(scrollregion=self.bwcanvas.bbox("all"))
		#####################
		webframe = tk.Frame(master)
		webframe.grid(row=1000, column=0)
		webname = tk.Label(webframe, text=r"Created by John W Kerns      -     ",)
		webname.pack(side="left")
		weblink = tk.Label(webframe, text=r"https://github.com/packetsar/acid", fg="blue", cursor="hand2")
		weblink.pack(side="left")
		weblink.bind("<Button-1>", self._open_web)
		versionlabel = tk.Label(webframe, text=r"           Version "+version+" (Python %s.%s.%s" % sys.version_info[:3]+")",)
		versionlabel.pack(side="left")
		#####################
		self.runbuttonimage = tk.PhotoImage(data=runimagedata)
		self.closebuttonimage = tk.PhotoImage(data=closeimagedata)
		#####################
		#self.rowlist = [0]
		self.checkdict = {}
	def _config_file_populate(self, cbox):
		#self.configentry.set(newvals[0])
		filelist = core.get_config_files()
		configlist = []
		for entry in filelist:
			configlist.append(entry["shortname"])
		cbox['values'] = configlist
	def _on_configure(self, event, canvasobject, window):
		core.debug(self, 2, "gui._on_configure called: Window size changing")
		#canvasobject.itemconfig(window, width=event.width)
		canvasobject.itemconfig(window, width=canvasobject.winfo_width())
		canvasobject.configure(scrollregion=canvasobject.bbox('all'))
	def _on_mousewheel(self, event):
		core.debug(self, 2, "gui._on_mousewheel called: Mouse scrolling")
		if abs(event.delta) > 100:  # If we are on a Windows system which uses values of 120
			self.bwcanvas.yview_scroll(int(-1*(event.delta/120)), "units")
		else:  # If we are on a Mac which uses values of 1
			self.bwcanvas.yview_scroll(int(event.delta * -1), "units")
	def update_height(self):
		core.debug(self, 2, "gui.update_height called: Updating canvas height")
		self.bwcanvas.update()
		self.bwcanvas.configure(scrollregion=self.bwcanvas.bbox("all"))
		#if self.bwcanvas.bbox("all")[3] < core.root.winfo_screenheight():
		#	width = str(self.master.winfo_width())
		#	height = str(self.bwcanvas.bbox("all")[3] + 10)
		#	self.master.geometry(width+'x'+height)
	def create_check(self, rownum=False):
		core.debug(self, 2, "gui.create_check called: Creating new check")
		if not rownum:
			rownum = self._next_row()
		core.debug(self, 2, "gui.create_check: Creating check on row %s" % str(rownum))
		checkparentframe = tk.Frame(self.bw, borderwidth=1, relief=tk.SUNKEN)
		self.checkdict.update({rownum:{"rownum": rownum}})
		checkparentframe.grid(row=rownum, column=0, sticky="nesw")
		checkparentframe.grid_columnconfigure(1, weight=1)
		self.checkdict[rownum].update({"checkparentframe": checkparentframe})
		#####################
		checkctrlframe = tk.Frame(self.checkdict[rownum]["checkparentframe"])
		checkctrlframe.grid(row=0, column=0, sticky="nesw")
		checkctrlframe.grid_columnconfigure(0, weight=1)
		self.checkdict[rownum].update({"checkctrlframe": checkctrlframe})
		#####################
		defaultmodule = tk.StringVar(self.checkdict[rownum]["checkparentframe"])
		defaultmodule.set("- Select Module -")
		self.checkdict[rownum].update({"defaultmodule": defaultmodule})
		#####################
		deletebutton = tk.Button(self.checkdict[rownum]["checkctrlframe"], image=self.closebuttonimage, command= lambda: self._delete_check(rownum, self.checkdict[rownum]["checkparentframe"]))
		deletebutton.grid(row=0, column=0, sticky="nw")
		self.checkdict[rownum].update({"deletebutton": deletebutton})
		#####################
		checkbutton = tk.Button(self.checkdict[rownum]["checkctrlframe"], image=self.runbuttonimage)
		checkbutton.grid(row=0, column=1, sticky="nw")
		self.checkdict[rownum].update({"checkbutton": checkbutton})
		#####################
		modulemenu = ttk.Combobox(self.checkdict[rownum]["checkctrlframe"], textvariable=self.checkdict[rownum]["defaultmodule"], width=15, justify=tk.CENTER)
		modulemenu['values'] = list(core.resources)
		modulemenu.state(['readonly'])
		modulemenu.grid(row=1, column=0, columnspan=2, sticky="w")
		self.checkdict[rownum].update({"modulemenu": modulemenu})
		#####################
		checkframe = shared.build_frame(self.checkdict[rownum]["checkparentframe"], 0, 1)
		self.checkdict[rownum].update({"checkframe": checkframe})
		modulemenu.bind("<<ComboboxSelected>>", lambda evente:core.select_module(rownum))
		core.loadedchecks.update({rownum: {"guiobj": self.checkdict[rownum]}})
		core.update_config("merge", {"id": rownum})
		#####################
		self.update_height()
		return self.checkdict[rownum]
	def _next_row(self):
		core.debug(self, 2, "gui._next_row called: Checking for new row")
		rowlist = []
		for check in core.runningconfig["config"]["checks"]:
			rowlist.append(int(check["id"]))
		if rowlist == []: # If there are no checks
			return 1
		rowlist.sort()
		lastnumber = rowlist[len(rowlist)-1]
		core.debug(self, 2, "gui._next_row: Returning row: %s" % str(lastnumber+1))
		return lastnumber+1
	def _delete_check(self, rownum, frameobj):
		core.debug(self, 2, "gui._delete_check called: Deleting check on row %s" % str(rownum))
		core.debug(self, 3, "gui._delete_check: Attempting to gracefully stopp check module")
		try:
			core.loadedchecks[rownum]["checkobj"].stop()
			core.debug(self, 3, "gui._delete_check: Successfully called stop")
		except KeyError:
			core.debug(self, 3, "gui._delete_check: Stop failed, likely empty check")
		core.debug(self, 3, "gui._delete_check: Resetting grid")
		frameobj.grid_forget()
		frameobj.destroy()
		core.debug(self, 3, "gui._delete_check: Deleting frame")
		del frameobj
		core.debug(self, 3, "gui._delete_check: Deleting from loadedchecks")
		del core.loadedchecks[rownum]
		core.update_config("clear", {"id": rownum})
		self.update_height()
	def _open_web(self, url):
		core.debug(self, 2, "gui._open_web called: Opening website")
		webbrowser.open_new(url.widget.cget("text"))




################## CORE ###################
import os
import re
import json
import threading

class core:
	module = "core"
	modulelist = [ping, http, debug]
	defaultconfig = {
			"config": {
				"checks":[
					{
						"id": 1, 
						"host": "www.google.com", 
						"module": "http", 
						"pattern": "href"
					}, 
					{
						"id": 2, 
						"host": "www.google.com", 
						"module": "ping", 
						"timeout": "5", 
						"repeat": 10
					},
					{
						"id": 3, 
						"host": "www.ping.com", 
						"module": "ping", 
						"timeout": "5", 
						"repeat": 100
					},
					{
						"id": 4, 
						"host": "8.8.8.1", 
						"module": "ping", 
						"repeat": 10
					},
					{
						"id": 5, 
						"host": "8.8.8.8", 
						"module": "ping", 
						"repeat": 10
					}
				]
			}
		}
	def __init__(self):
		# No debugging here since debugging modules arent loaded yet
		shared.detect_os()
		self.resources = self._instantiate()
		self.runningconfig = {"config": {"checks":[]}}
		self.loadedchecks = {}
		self.debuggers = {}
	def _instantiate(self):
		# No debugging here since debugging modules arent loaded yet
		result = {}
		for eachmodule in self.modulelist:
			obj = eachmodule()
			result.update({obj.module:{"module": obj.module, "class": eachmodule}})
			del obj
		return result
	def select_module(self, rownum, config=None):
		core.debug(self, 2, "core.select_module called: Starting build of check")
		checkframedict = self.loadedchecks[rownum]['guiobj']
		modulemenu = checkframedict['modulemenu']
		core.debug(self, 3, "core.select_module: Selected module is %s" % modulemenu.get())
		core.debug(self, 3, "core.select_module: Resetting grid")
		checkframedict['checkframe'].grid_forget()
		checkframedict['checkframe'] = shared.build_frame(self.gui.checkdict[rownum]["checkparentframe"], 0, 1)
		core.debug(self, 3, "core.select_module: Instantiating module")
		newcheckobj = self.resources[modulemenu.get()]["class"]()
		if config == None:
			core.debug(self, 3, "core.select_module: Starting check module with blank config")
			newcheckobj.start({"id": rownum}, checkframedict)
		else:
			core.debug(self, 3, "core.select_module: Starting check module with config:\n"+str(config))
			newcheckobj.start(config, checkframedict)
		self.loadedchecks[rownum]["checkobj"] = newcheckobj
		self.gui.update_height()
	def _load_startup_config(self):
		# No debugging here since debugging modules arent loaded yet
		if self._file_exists_(defaultconfigfile):
			file = open(defaultconfigfile, "r")
			config = json.loads(file.read())
			file.close()
		else:
			config = self.defaultconfig
		for checkconfig in config["config"]["checks"]:
			checkframedict = self.gui.create_check(checkconfig["id"])
			self.loadedchecks[checkconfig["id"]]["guiobj"] = checkframedict
			try:  # Exception in case module is not selected in check
				checkframedict['modulemenu'].set(checkconfig["module"])
				self.select_module(checkconfig["id"], checkconfig)
			except KeyError:
				pass
	def start(self):
		# No debugging here since debugging modules arent loaded yet
		if gui_ready:
			self._start_gui()
			try:
				self._load_startup_config()
			except AttributeError:
				pass
			self.root.mainloop()
		else:
			shared.console("no gui!!!")
	def _start_gui(self):
		self.root = tk.Tk()
		self.gui = gui(self.root)
	def run_all(self):
		core.debug(self, 2, "core.run_all called: Running all active checks")
		for check in self.loadedchecks:
			core.debug(self, 3, "core.run_all: Trying run check in row %s" % check)
			try:
				thread = threading.Thread(target=self.loadedchecks[check]["checkobj"].run)
				thread.start()
			except KeyError:  # If loaded check has no module selected
				core.debug(self, 3, "core.run_all: Check in row %s has no module selected" % check)
		core.debug(self, 3, "core.run_all: Complete: All checks kicked off")
	def update_config(self, mode, data):
		core.debug(self, 2, "core.update_config called: Updating running config")
		matched = False
		index = 0
		# Find the proper check in running config, set index to check id
		for check in self.runningconfig["config"]["checks"]:
			if check["id"] == data["id"]:
				matched = True
				break
			index += 1
		if mode == "merge":
			core.debug(self, 2, "core.update_config: Merging config:\n"+str(data))
			if matched:
				self.runningconfig["config"]["checks"][index] = data
			else:
				self.runningconfig["config"]["checks"].append(data)
		elif mode == "clear":
			core.debug(self, 2, "core.update_config: Clearing config")
			del self.runningconfig["config"]["checks"][index]
		core.debug(self, 2, "core.update_config: New config:\n"+str(self.runningconfig))
	def _file_exists_(self, localfile):
		try:
			file = open(localfile, "r")
			file.close()
			return True
		except IOError:
			return False
	def save_config(self):
		self.debug(self, 1, "core.save_config called: Saving Config...")
		config = json.dumps(self.runningconfig, indent=4, sort_keys=True)
		self.debug(self, 1, "core.save_config: New Config:\n%s" % config)
		file = open(defaultconfigfile, "w")
		file.write(config)
		file.close()
		self.debug(self, 3, "core.save_config: Saved Successfully")
	def config_file_change(self, comboobj):
		self.debug(self, 1, "core.config_file_change called: Reloading Configs")
		configfiles = self.get_config_files()
		self.debug(self, 2, "core.config_file_change: Found files: "+str(configfiles))
	def _get_wd_files(self):
		filelist = []
		for root, directories, filenames in os.walk(os.getcwd()):
			for filename in filenames:
				if os.path.isfile(filename):
					fullpath = os.path.join(root, filename)
					filelist.append({"filename": filename, "fullpath": fullpath})
			return filelist
	def get_config_files(self):
		result = []
		allfiles = self._get_wd_files()
		regex = "\\"+defaultconfigext+"$"
		for fileentry in allfiles:
			if re.findall(regex, fileentry["filename"]) != []:
				shortname = fileentry["filename"].replace(defaultconfigext, "")
				fileentry.update({"shortname": shortname})
				result.append(fileentry)
		return result
	def _pick_config_file(self):
		filelist = self.get_config_files()
		filenamedict = {}
		index = 0
		for entry in filelist:
			if entry["filename"].lower() == defaultconfigfile:
				return entry["fullpath"]
			else:
				filenamedict.update({entry["shortname"]: index})
			index += 1
		sortedfiles = list(filenamedict)
		sortedfiles.sort()
		pickedfileindex = filenamedict[sortedfiles[0]]
		return filelist[pickedfileindex]["fullpath"]
	def debug(self, obj, level, data):
		params = (obj, level, data)
		for q in self.debuggers.values():
			try:
				q.put(params)
			except KeyError as error:
				shared.console("Debug Queue Failure: %s" % data)
###################################################################
######################### </CORE CLASSES> #########################
###################################################################




newcheckimagedata = '''R0lGODlhFAAUAPcAAAAAAJLQUJLQUQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAP8ALAAAAAAUABQA
AAhWAP8JHDhQgACCCBMKDMDwoMKHDAM4fJgw4kSKBC1irNhwI0KNHgdGDEBxpMmTEf8JQMnS4sqW
LA8anPlyJE2DJVOGXNhx5z+QO4GGFOqR6EajG3E+DAgAOw=='''

runimagedata = '''R0lGODlhFAAPAPcAAAAAADGFmzOGnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAP8ALAAAAAAUAA8A
AAg+AP8JHEiwoMGDBAMgXCgwgEKGBx0+hJhQYkGJGDNiHChAo8eN/zp+HBly5MeBJjVSRGlxZUOH
LlnGRDkTYkAAOw=='''

runallimagedata = '''R0lGODlhIgAUAPcAAAAAADGFmzSGnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAP8ALAAAAAAiABQA
AAhvAP8JHEiwoMGDCBMWDGAwAEOFEAc6XDgxIkSHDwVizGjx4EaJHzt6DLmxokiQJf+VNPlPwMqX
MGMOdBmzpk2BNG3qfNlyp8+UOX/uxCnU50mNK1UmPYoUY1OnTJ+iZMkUqtSoIClyxLpVKdavAgMC
ADs='''

closeimagedata = '''R0lGODlhDwAPAPcAAAAAAGEmIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAP8ALAAAAAAPAA8A
AAg9AP8JHEiwoMAAAQz+QzgQIUOCDhMujNiQ4sGIGCVWzKgRYkaFEy0q5DiSY8eQDDFufIhSosiL
LFl6BEkzIAA7'''

saveimagedata = '''R0lGODlhGQAZAPcAAAAAAFiAs1mBtFqCtF6EtV6FtmSJuWaLumyPvG+RvXCSv
nSVwIOhxoShx4Six4ikyYqmyo+qzJiw0Jmy0Zuz0p200qK41KO51am+2LDD27PF3LTG3bbH3rjJ37nK3
7vL4LzM4L3N4b7O4b/O4sDP4sHQ48TS5MbU5cnW5srX58vY58zY6AAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAACH5BAEAAP8ALAAAAAAZABkAAAjdAP8JHEiwoMGCAQIwWIHihMOHECGumJBQY
EIGHQYk3MixYwSKAf5pVAjCQIGTKFOmlABS5MUVJkTInElz5oiJFUcy4CCgo8+NEFrqFIHggNGjSJFWE
PpShIenUKNGTcFU4YafWB9UZUBiQYKvYMOGtVBVwQkVaNOqXZuiQU6scH26jEs35Mi6cOfixap3r9y7f
jv2nVCisOHDhiFw7PthhePHkB9jWAy4cYkKFC5ElkyZY+MHGzVsXjF5I+MVDjZmGF06pMWNjVMnXL25N
EHPKyQkJBCCteuDwIMPDAgAOw==
'''

logoimagedata = '''R0lGODlhlgCWAPcAAAAAAACwUAGwUQKxUgSxUgSxUwaxVAayVAmy
VgqyVw20WRC0WxS2Xha2Xxy4Yx65ZB+5ZSK6ZyW7aSa7aim8bCq8bSy9bi29by2+by6+cDC
+cTXAdDvCeD3Cej/De0PEfjGFmzKGmzKGnDSGnDSHnTaInTaInjiJnjmKnzqLoDyLoDyMoD
6MoUCNokCOokKOo0OPpEOQpESQo0SQpEWRpUeSpUeSpkiSpkqTp0uUp0yUp0yVqE6WqVCXq
lGYqlKYq1SZq1WarFabrVibrVicrVmcrludr1uer1yer16fsF6gsWCgsWKhsmKis2Sjs2Sj
tGaktGeltWiltWmmtmunt2ynt2yot22ouG+puXCquXGrunOsunOsu3Wtu3WtvHauvHeuvXm
vvXmvvnqwvnyxv0rGg1jLjGDNkmLNk2LOk2POlGnQmG3RmnTTn3bUoXnVo3vWpH3WpYCzwY
C0wYK0woS2w4W3xIi4xYq5xou6xou7x4y6x468yI+9yZC9yJC9yZG+yZK+ypO/y5S/yoLYq
YTYqobZrInZrYjarYraro3bsI7bsZfet5jfuJrfuqHhvqHhv5XAy5bBzJnCzZvDzpzEzpzE
z57F0KDG0KDH0aPI0qTJ0qXJ06XK06jL1KnL1arM1avN1qzN163O16/P2LDQ2LHR2aXjwQA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BA
EAAP8ALAAAAACWAJYAAAj/AP8JHEiwoMGDCBMqXMiwocOHECNKnEixosWLGDNq3Mixo8ePI
EOKHEmypMmTKFOqXMmypcuQoyxFirQnzyBJmEC93FkSlJ0lLESAGEq0qFEQIlgoofOJp9OK
e4qMOEq1KlUSQfA83ZpQkxMTVsOKPVpiSSauWzkhETq2rduhIoacRdvSC9i3ePGSuEI35Y+
8gAPzCNVXZKcXgRMHDlLYo6cZiiPjHdG4Iw/JmN1KqqxxSubPYn1wxrgpBejTVEWMvpgEtW
ujXlZTLIXitW0QJmRPHHP7thzdEYP0tq0a+EMWw21LMe6wRHLbChtRCEC9OoRDlS2FeP4aR
cIL1cNX/39QWBB322EQKhDPPsABunrOQz+4oH3791v/nCdRQ4qduQhhcscUN9wVFmUGcWCf
fRE8NUlyJCDxh0WBJDEVVTsctOCCivAUSm97eaTFCUZ1YVAGG9o3AU8k2BZEJyMZQdQkBqV
onwA7kYiaCFOgpEVxBIFnY3sv6bBjjzwNaR8jLV2BGmNOCamkeI6wlMlpKHCy1ZREsuTcZ0
9whSKX4RXAUg+fkUAJWmSK18FKe3z2Al0atBkeSxdKBiWbdlJ3wUrCYRYmXWP2uRIomfHVV
5/UZbAScpJtUZiUdsKJGZKLMuqoSi1GhkRjlLa5Uh2S4VAZowFsmlKegeUGKqqWRv82yqmM
YrDSCpFpURkGsKqkSWQzcIaqBStdphhndTLKUmRYCFvrSmIo5mpjyRq6Um2J3eFsn3+upJh
3lRVa6UpfKMbHtnaqmhK2gJHAGa/KLptYerRyy5J+iXEWKpktFZFYD+i22e1KrOJFY2PwWi
svYEAWNmxLlvxbWbXjsgRGtvXaSWxLxgI2ca8tsZXXtJn2aatLif3QmLiivpTYGI2hqu5Kn
SRmyaQgt+RHvg4zOnBLc/BM175c8qRFYA1ThAgFA1Q3QAWJYITqyS81EdgKF9Vn3wKnVET0
lE75CxgNFbkhQIoCtEHRwzwFmlcOFBUyJSESscyvUx3jxQNFTSs4OYBEqP78Ut5viSbRBmQ
2ABHFLTv1F2B7A96mBw/JvJUQgd0gURx9vtGQ3UVvJSNgMEhURp9/M2T/+VZSBAYuRNP1yc
BCoIPNVbmBSSQBqpQntPpWpOYe0QeoBuD5QV8rSZckQj/URvGp1+hzX4kFIjmqsxeU/JCFJ
aYoRBMUH0DvA7FNV2I1THR28XAMVLvyhRmIV9IOnSE+AeUzunFfRzQPUQXiUxzj7lYYOiTm
CxRJgPgcEDjOJKYFFIGE+Io3mmNRRA0T7NPM+sKuvPyGIgDMIAEr46TAsMAiCBDhlDbYF09
YsCLrU2GKdLOdwHyqIvaT4YZYWJgbvBCEOlwQcPAVmCpcRIFBFA/VZBMZqSXxTsbxYWIGVR
E0PJE6+9MN835IEQtckTkCKZjeMIJEHS4ROFCIzB4w/xJDFYJxIJFBkEVyqELBGQdNisnQR
UIowjcORBSSgdkRRchD4NBAMlqyyCP66MeBICoy7roIBsVnxzceMjIqwAgf49XIgZgCM3Ma
5PQ6SRCxRSZ9FoFEG0dISoGITDHBmmOfstjKf5AhMye0yCZtV0uCIAYzJTCFRcqopErWEjT
aiiCXotdLgoQBNEeoyBqmpLZmGkSKmUGBTiZihiGlwZoIEWNkkkARQxhgQQlYBDgRcqXTkK
AOFFmD1qrDADasUyFccI0KrJeSScyhlUR4jQnsYJI91EaPpMTmjpggEimILJKthJRtSpCFW
WlEC/IjSjM7SJwcyIEUE6HDDsRJFOAE9vJL3BFBDISgBTr8YRKXuMQkAlGHLiRhBiSlSiab
qSP5oAacpvHpaagATsgI9TP0ayUQjvoZeILTM0yVzAnuCYioSoYM9/wHrqyKtKz+w2pcBcy
e1mkJjoZ1LJXw6j+ccNa3yDGrppBBW9tCNrX+ow8onWtVqKhWOnRKr0cZQSnsOpA55FWvJh
AkYQkCiF+21QUTWmxCovDXo5KgCZJ1CCakIp8RECGtmZXIFcyKpSlsIrQYucQVbCAnK9wMt
R/pBB6u8AMaZNQoJHiBD6hQBwDB9rfADa5wh0vc4nIlIAA7'''



if __name__ == '__main__':
	shared = shared()
	core = core()
	core.start()

