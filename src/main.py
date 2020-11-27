'''
    NVCAT: A (N)etwork (V)isibility (C)onfiguration (A)nalysis (T)ool
    by Gabriel Siewert
    August 2020-December 2020
'''

from datetime import datetime
from pandas.io.clipboard import copy
from re import search
from tabulate import tabulate
from tkinter import *
from tkinter import filedialog
from tkinter.messagebox import showinfo
from tkinter.simpledialog import askstring

# Custom modules
from platforms import *
from report_main import *
from report_rw import *
from send_email import *


ROOT_COLOR = "#FFFFFF"
PASSWORD_PROTECTION = True

PROMPT = ("Select device type.")
DEVICE_TYPES = ["Router", "Switch", "Firewall"]
PLATFORMS = get_platforms()
LOOK_FOR = {"Router":   ["NetFlow", "SPAN", "HTTP"],
            "Switch":   ["NetFlow", "SPAN", "HTTP"],
            "Firewall": ["ACL Values"]}

W = 300
H = 200

class App():
    # Root window setup
    def __init__(self):
        self.specs = {}
        self.reportFlag = True
        self.root = Tk()
        self.introMsg = Message(self.root, text=PROMPT,
                        bg=ROOT_COLOR, width=W-20)

        self.choice = IntVar(self.root)
        self.passwdProtection = IntVar()
        self.passwdProtection.set(1)
        self.rBtn = []
        for i in range(0, 3):
            self.rBtn.append(Radiobutton(self.root, text=DEVICE_TYPES[i],
                             bg=ROOT_COLOR, value=i+1, variable=self.choice))
        self.resetBtn = Button(self.root, text="Restart", command=self.restart,
                        highlightbackground=ROOT_COLOR)
        self.nextBtn = Button(self.root, text="Next", command=self.platform_select,
                         highlightbackground=ROOT_COLOR)
        self.passwdProtectionBtn = Checkbutton(self.root,
                                    text="Password Protection",
                                    bg=ROOT_COLOR,
                                    variable=self.passwdProtection)
        self.readReportBtn = Button(self.root, text="Read Report", command=self.read_report,
                               highlightbackground=ROOT_COLOR)
        qBtn = Button(self.root, text="Quit", command=lambda:self.quit("ROOT"),
               highlightbackground=ROOT_COLOR)

        self.introMsg.place(x=10, y=10)
        for i in range(0, 3):
            self.rBtn[i].place(x=30, y=30+20*i)
        self.passwdProtectionBtn.place(x=W-160, y=H-50)
        self.nextBtn.place(x=10, y=95)
        self.resetBtn.place(x=W-130, y=H-30)
        self.readReportBtn.place(x=W-233, y=H-30)
        qBtn.place(x=W-59, y=H-30)

        self.root.title("NVCAT")
        self.root.geometry(str(W)+'x'+str(H)+"+0+20")
        self.root["bg"] = ROOT_COLOR
        self.root.resizable(False, False)
        self.root.mainloop()

    def platform_select(self):
        selection = self.choice.get() - 1
        if selection == -1:
            return
        self.passwdProtection = self.passwdProtection.get()
        self.choice.set(0)
        self.specs["type"] = self.rBtn[selection]["text"]
        self.introMsg["text"] = "Select platform."
        self.readReportBtn["state"] = DISABLED
        self.passwdProtectionBtn["state"] = DISABLED
        self.readReportBtn.place_forget()
        self.passwdProtectionBtn.place_forget()
        for btn in self.rBtn:
            btn.place_forget()

        data = [""]
        pfList = [pf for pf in PLATFORMS[self.specs["type"]]]
        for pf in pfList:
            data.append(pf)

        self.platformVar = StringVar()
        self.platformVar.set("")

        self.dropdownList = OptionMenu(self.root, self.platformVar, *data)
        self.dropdownList.config(width=len(max(pfList, key=len))+3)
        self.dropdownList.config(bg=ROOT_COLOR)
        self.dropdownList.place(x=10, y=50)
        self.nextBtn["command"] = self.look_for_select

    def look_for_select(self):
        selection = self.platformVar.get()
        if not selection:
            return
        self.specs["platform"] = selection
        self.introMsg["text"] = "Select what to look for."
        self.dropdownList.place_forget()
        self.cBtn = []
        self.cVar = [IntVar(), IntVar(), IntVar()]
        self.look_for = LOOK_FOR
        if (self.specs["type"] != "Firewall" and
            "IOS" not in self.specs["platform"]):
            self.look_for[self.specs["type"]].remove("HTTP")
        for i in range(0, len(self.look_for[self.specs["type"]])):
            self.cBtn.append(Checkbutton(self.root,
                             text=self.look_for[self.specs["type"]][i],
                             bg=ROOT_COLOR, variable=self.cVar[i]))
        for i in range(0, len(self.look_for[self.specs["type"]])):
            self.cBtn[i].place(x=30, y=30+20*i)
        self.nextBtn["command"] = self.local_remote_select

    def local_remote_select(self):
        if 1 not in [x.get() for x in self.cVar]:
            return
        self.specs["search"] = []
        for i in range(0, 3):
            if self.cVar[i].get() == 1:
                self.specs["search"].append(self.cBtn[i]["text"])
        for btn in self.cBtn:
            btn.place_forget()

        self.rBtn[0]["text"] = "Local"
        self.rBtn[1]["text"] = "Remote"
        for i in range(0, 2):
            self.rBtn[i].place(x=30, y=30+20*i)
        self.introMsg["text"] = "Select local or remote data retrieval."
        self.nextBtn["command"] = self.process_local_remote

    def process_local_remote(self):
        selection = self.choice.get() - 1
        if selection not in [0, 1]:
            return
        self.choice.set(0)
        self.specs["local"] = True if selection == 0 else False
        if self.specs["local"]:
            self.batch_select()
        else:
            self.specs["config"] = None
            self.remote_ip_address()

    def remote_ip_address(self):
        for btn in self.rBtn:
            btn.place_forget()
        self.introMsg["text"] = "Specify device IP address."
        self.IPAddressMsg = Message(self.root, text="IP Address:",
                                    bg=ROOT_COLOR, width=W-20)
        self.IPAddressEntry = Entry(self.root, highlightbackground=ROOT_COLOR,
                                    width=10)
        self.IPAddressMsg.place(x=10, y=50)
        self.IPAddressEntry.place(x=90, y=50)
        self.nextBtn["command"] = self.remote_authentication

    def remote_authentication(self):
        IPAddressRegex = re.compile("([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
        if not self.IPAddressEntry.get():
            return
        IPAddressRegex = IPAddressRegex.search(self.IPAddressEntry.get())
        if not IPAddressRegex:
            return
        self.IPAddressMsg.place_forget()
        self.IPAddressEntry.place_forget()
        self.specs["ip_address"] = IPAddressRegex.group(1)
        self.introMsg["text"] = "Select SSH authentication method."
        self.rBtn[0]["text"] = "Password"
        self.rBtn[1]["text"] = "SSH Key"
        for i in range(0, 2):
            self.rBtn[i].place(x=30, y=30+20*i)
        self.nextBtn["command"] = self.remote_process_auth

    def remote_process_auth(self):
        selection = self.choice.get() - 1
        if selection not in [0, 1]:
            return
        self.specs["batch"] = None
        self.specs["authentication"] = "password" if selection == 0 else "ssh_key"
        for btn in self.rBtn:
            btn.place_forget()
        if self.specs["authentication"] == "password":
            self.remote_ssh_password()
        elif self.specs["authentication"] == "ssh_key":
            self.remote_ssh_key()

    def remote_ssh_password(self):
        self.introMsg["text"] = "Enter username and password."
        self.remoteUserMsg = Message(self.root, text="Username:",
                                    bg=ROOT_COLOR, width=W-20)
        self.remoteUserEntry = Entry(self.root, highlightbackground=ROOT_COLOR,
                                    width=10)
        self.remotePwdMsg = Message(self.root, text="Password:",
                                    bg=ROOT_COLOR, width=W-20)
        self.remotePwdEntry = Entry(self.root, highlightbackground=ROOT_COLOR,
                                    width=10, show='*')
        self.remoteUserMsg.place(x=10, y=35)
        self.remoteUserEntry.place(x=135, y=35)
        self.remotePwdMsg.place(x=10, y=65)
        self.remotePwdEntry.place(x=135, y=65)
        self.nextBtn["command"] = self.report_select

    def remote_ssh_key(self):
        self.introMsg["text"] = "Specify SSH private key file. You must have already added your SSH public key to the network device."
        self.pathEntry = Entry(self.root, highlightbackground=ROOT_COLOR,
                                      width=10)
        self.dialogBtn = Button(self.root, text="Select File",
                                 command=self.remote_ssh_key_file_dialog,
                                 highlightbackground=ROOT_COLOR)
        self.pathEntry.place(x=15, y=65)
        self.dialogBtn.place(x=115, y=65)
        self.nextBtn["command"] = self.report_select

    def remote_ssh_key_file_dialog(self):
        self.specs["ssh_key_file"] = filedialog.askopenfilename()
        if not self.specs["ssh_key_file"]:
            return
        self.pathEntry.delete(0, "end")
        self.pathEntry.insert(0, self.specs["ssh_key_file"])
        self.pathEntry["state"] = DISABLED
        self.dialogBtn["state"] = DISABLED

    def batch_select(self):
        self.rBtn[0]["text"] = "Individual"
        self.rBtn[1]["text"] = "Batch"
        self.introMsg["text"] = "Select individual or batch analysis."
        self.nextBtn["command"] = self.config_select

    def config_select(self):
        selection = self.choice.get() - 1
        if selection not in [0, 1]:
            return
        self.specs["batch"] = False if selection == 0 else True
        for btn in self.rBtn:
            btn.place_forget()
        self.pathEntry = Entry(self.root, highlightbackground=ROOT_COLOR, width=10)
        self.pathEntry.place(x=15, y=50)
        self.introMsg["text"] = "Specify a folder containing configuration files."\
                                if self.specs["batch"] else\
                                "Specify a configuration file."
        btnText = "Select Folder" if self.specs["batch"] else "Select File"
        self.dialogBtn = Button(self.root, text=btnText,
                              command=self.config_dialog,
                              highlightbackground=ROOT_COLOR)
        self.dialogBtn.place(x=115, y=50)
        self.nextBtn["command"] = self.report_select

    def config_dialog(self):
        if self.specs["batch"]:
            self.specs["config"] = filedialog.askdirectory()
        else:
            self.specs["config"] = filedialog.askopenfilename()
        if not self.specs["config"]:
            return
        self.pathEntry.delete(0, "end")
        self.pathEntry.insert(0, self.specs["config"])
        self.pathEntry["state"] = DISABLED
        self.dialogBtn["state"] = DISABLED

    def report_select(self):
        if not self.specs["batch"]:
            if (self.specs["local"] or self.specs["authentication"] == "ssh_key") and \
                not self.pathEntry.get():
                return
            if not self.specs["local"] and self.specs["authentication"] == "password" and \
                  (not self.remoteUserEntry.get() or not self.remotePwdEntry.get()):
                return
        if self.specs["local"]:
            self.specs["config"] = self.pathEntry.get()
            if self.specs["batch"] and not get_files(self.specs["config"]):
                showinfo("Error", "Directory is empty. Please try again.")
                return
            else:
                self.specs["config"] = self.pathEntry.get()
        elif self.specs["authentication"] == "password":
            self.remoteUserMsg.place_forget()
            self.remotePwdMsg.place_forget()
            self.remoteUserEntry.place_forget()
            self.remotePwdEntry.place_forget()
            self.specs["username"] = self.remoteUserEntry.get()
            self.specs["password"] = self.remotePwdEntry.get()
            self.pathEntry = Entry(self.root, highlightbackground=ROOT_COLOR, width=10)
            self.dialogBtn = Button(self.root, text="Select File",
                                  command=self.remote_ssh_key_file_dialog,
                                  highlightbackground=ROOT_COLOR)
            self.pathEntry.place(x=15, y=50)
            self.dialogBtn.place(x=115, y=50)
        elif self.specs["authentication"] == "ssh_key":
            self.specs["ssh_key_file"] = self.pathEntry.get()
            self.pathEntry.place(x=15, y=50)
            self.dialogBtn.place(x=115, y=50)
        self.introMsg["text"] = "Specify a destination for the report files."\
                                if self.specs["batch"] else\
                                "Specify the report file path."
        self.dialogBtn["state"] = NORMAL
        self.pathEntry["state"] = NORMAL
        self.pathEntry.delete(0, "end")
        self.dialogBtn["command"] = self.report_dialog
        self.nextBtn["command"] = self.enter_pwd
            
    def report_dialog(self):
        if self.specs["batch"]:
            self.specs["report"] = filedialog.askdirectory()
        else:
            self.specs["report"] = filedialog.asksaveasfilename(defaultextension=".txt")
        if not self.specs["report"]:
            return
        self.pathEntry.insert(0, self.specs["report"])
        self.pathEntry["state"] = DISABLED
        self.dialogBtn["state"] = DISABLED

    def enter_pwd(self):
        if self.specs["batch"]:
            if not self.pathEntry.get():
                return
            self.pathEntry["state"] = DISABLED
            self.dialogBtn["state"] = DISABLED
            self.specs["report"] = self.pathEntry.get()
            if get_files(self.specs["report"]):
                showinfo("Warning", "This directory is not empty.")
            self.pathEntry.place_forget()
            self.dialogBtn.place_forget()
        else:
            if not self.pathEntry.get():
                return
            self.pathEntry["state"] = DISABLED
            self.dialogBtn["state"] = DISABLED
            self.specs["report"] = self.pathEntry.get()
            self.pathEntry.place_forget()
            self.dialogBtn.place_forget()
        if self.passwdProtection:
            self.introMsg["text"] = "Enter a password to encrypt the report."
            self.pwd1Msg = Message(self.root, text="Enter password:",
                                   bg=ROOT_COLOR, width=W-20)
            self.pwd2Msg = Message(self.root, text="Confirm password:",
                                   bg=ROOT_COLOR, width=W-20)
            self.pwd1Entry = Entry(self.root, highlightbackground=ROOT_COLOR,
                                   width=10, show='*')
            self.pwd2Entry = Entry(self.root, highlightbackground=ROOT_COLOR,
                                   width=10, show='*')
            self.pwd1Msg.place(x=10, y=35)
            self.pwd1Entry.place(x=135, y=35)
            self.pwd2Msg.place(x=10, y=65)
            self.pwd2Entry.place(x=135, y=65)
            self.nextBtn["command"] = self.store_pwd
        else:
            self.read_report()

    def store_pwd(self):
        self.pwd1, self.pwd2 = self.pwd1Entry.get(), self.pwd2Entry.get()
        if not self.pwd1 or not self.pwd2:
            return
        if self.pwd1 != self.pwd2:
            showinfo("Error", "Passwords must match.")
            return
        if not self.fips_compliant(self.pwd1):
            showinfo("Error", "Passwords must be FIPS-compliant.")
            return
        self.pwd1Entry["state"] = DISABLED
        self.pwd2Entry["state"] = DISABLED
        self.generateReportBtn = Button(self.root, text="Generate Report",
                                        command=self.read_report,
                                        highlightbackground=ROOT_COLOR)
        self.generateReportBtn.place(x=100, y=95)
        self.nextBtn["state"] = DISABLED

    def read_report(self):
        # Coming from front page
        self.introMsg["text"] = "Specify the report file path."
        if not self.specs:
            for btn in self.rBtn:
                btn.place_forget()
            self.nextBtn.place_forget()
            self.pathEntry = Entry(self.root, highlightbackground=ROOT_COLOR,
                                       width=10)
            self.dialogBtn = Button(self.root, text="Select File",
                                  command=self.read_report_dialog,
                                  highlightbackground=ROOT_COLOR)
            self.readReportBtn["command"] = self.read_report_page
            self.pathEntry.place(x=15, y=50)
            self.dialogBtn.place(x=115, y=50)
            self.readReportBtn.place(x=10, y=95)
        # Coming from last page
        else:
            if self.passwdProtection:
                self.specs["passwd"] = self.pwd1
            else:
                self.specs["passwd"] = None
            if self.specs["batch"]:
                self.specs["report_aggregate"] = os.path.join(self.specs["report"], '')+\
                                                 self.specs["config"].split('/')[-1]+\
                                                 "-summary.txt"
            report_generation(self.specs)
            self.nextBtn.place_forget()
            if self.specs["passwd"]:
                self.pwd1Msg.place_forget()
                self.pwd2Msg.place_forget()
                self.pwd1Entry.place_forget()
                self.pwd2Entry.place_forget()

            if self.specs["batch"] or not self.specs["passwd"]:
                if self.specs["batch"]:
                    self.pathEntry = Entry(self.root, highlightbackground=ROOT_COLOR,
                                                  width=10)
                    self.dialogBtn = Button(self.root, text="Select File",
                                             highlightbackground=ROOT_COLOR)
                    self.specs["report"] = self.specs["report_aggregate"]
                if not self.specs["passwd"]:
                    self.generateReportBtn = Button(self.root, text="Generate Report",
                                                    highlightbackground=ROOT_COLOR)
                self.dialogBtn["state"] = DISABLED

            self.pathEntry.delete(0, "end")
            self.pathEntry.insert(0, self.specs["report"])
            self.pathEntry["state"] = DISABLED
            self.pathEntry.place(x=15, y=50)
            self.dialogBtn.place(x=115, y=50)
            self.generateReportBtn["text"] = "Read Report"
            self.generateReportBtn.place(x=10, y=95)
            self.generateReportBtn["command"] = self.read_report_page

    def read_report_dialog(self):
        self.specs["report"] = filedialog.askopenfilename()
        if not self.specs["report"]:
            return
        self.pathEntry.delete(0, "end")
        self.pathEntry.insert(0, self.specs["report"])
        self.pathEntry["state"] = DISABLED
        self.dialogBtn["state"] = DISABLED

    def read_report_page(self):
        # Set up page to enter report file path and password to decrypt file
        if not self.pathEntry.get():
            return
        self.pathEntry["state"] = DISABLED
        self.dialogBtn["state"] = DISABLED
        self.specs["report"] = self.pathEntry.get()
        file_encrypted = check_report(self.specs["report"])
        if not file_encrypted:
            readPwd = None
        else:
            readPwd = askstring("Decrypt Report",
                                 "Enter password to decrypt report contents.",
                                 parent=self.root, show='*')
        report = read_report(self.specs["report"], readPwd)
        if report:
            report, csv = report
            self.readReportBtn["state"] = DISABLED
            self.reportFlag = True
            if "type" in self.specs:
                self.generateReportBtn["state"] = DISABLED
            self.reportText = report
            self.reportCSV = csv
            self.reportWindow = Toplevel(self.root)
            self.scrollbar = Scrollbar(self.reportWindow)
            self.scrollbar.pack(side=RIGHT, fill=Y)
            self.report = Text(self.reportWindow, font=("Courier", 12),
                          yscrollcommand = self.scrollbar.set)
            self.report.pack(fill=BOTH, expand=True)
            self.scrollbar.config(command=self.report.yview)
            self.copyReportBtn = Button(self.reportWindow, text="Copy Report",
                                        command=self.copy_report)
            self.copyReportCSVBtn = Button(self.reportWindow, text="Copy Table (.csv)",
                                        command=self.copy_report_csv)
            self.sendEmailBtn = Button(self.reportWindow, text="Notify Admin",
                                        command=self.send_email)
            self.copyReportBtn.pack(side=RIGHT)
            self.copyReportCSVBtn.pack(side=RIGHT)
            self.sendEmailBtn.pack(side=LEFT)
            self.report.insert(END, report)
            self.report["state"] = DISABLED
            self.reportWindow.title("Visibility Report")
            reportWidth = int(len(max(report.split('\n'),
                                           key=len))*7.5)
            self.reportWindow.geometry(str(int(reportWidth))+'x'+str(H*2)+'+'+str(W+5)+"+20")
            self.reportWindow.mainloop()
        else:
            showinfo("Error", "Invalid credentials.")

    def copy_report(self):
        copy(self.reportText)
        self.copyReportBtn["text"] = "Report Copied!"

    def copy_report_csv(self):
        copy(self.reportCSV)
        self.copyReportCSVBtn["text"] = "CSV Copied!"

    def send_email(self):
        admin_email = askstring("Notify Administrator",
                             "Enter email address of administrator.",
                             parent=self.reportWindow)
        try:
            notify(admin_email, self.reportText)
        except Exception:
            showinfo("Error", "Invalid recipient email address.")

    # Source: https://access.redhat.com/documentation/en-us/jboss_enterprise_application_platform/6.3/html/security_guide/fips_140-2_compliant_passwords
    def fips_compliant(self, pwd):
        if len(pwd) < 7:
            return False
        c = {}
        c["digits"] = 1 if any(char.isdigit() for char in pwd[:-1]) else 0
        c["lower"] = 1 if any(char.islower() for char in pwd) else 0
        c["upper"] = 1 if any(char.isupper() for char in pwd[1:]) else 0
        c["special"] = 1 if any(not char.isalnum() for char in pwd) else 0
        c["non_ascii"] = 1 if any(ord(char) >= 128 for char in pwd) else 0
        if sum(c.values()) < 3:
            return False
        return True

    # Restart program
    def restart(self):
        self.quit("ROOT")
        self.__init__()

    # Close window according to msg value
    def quit(self, msg):
        if msg == "ROOT":
            window = self.root
        window.destroy()

app = App()
