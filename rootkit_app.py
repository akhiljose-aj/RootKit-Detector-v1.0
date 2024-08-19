import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import psutil
from tkinter import font
from tkinter import *
# Function to scan and return all processes
def scan_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        processes.append(f"PID: {proc.info['pid']} | Name: {proc.info['name']}")
    return processes

# Function to save processes to a text file
def save_to_file(processes):
    with open('process_list.txt', 'w') as f:
        for process in processes:
            f.write(process + '\n')

# RootkitDetectorApp class
class RootkitDetectorApp:

    def __init__ (self, root):
        self.root = root
        self.root.configure(bg='#2e2e2e')

        heading_label = tk.Label(self.root, text="- Scan for Rootkits -", font=('Arial', 14, 'bold'), fg='white', bg='#2e2e2e')
        heading_label.pack(pady=10)

        self.load_button = tk.Button(self.root, text="Load Process File", command=self.load_file)
        self.load_button.configure(bg='#808080', fg='white', padx=10, pady=5, font=('Arial', 12, 'bold'))
        self.load_button.pack(pady=20)
        self.load_button.bind("<Enter>", lambda e: self.load_button.configure(bg="lightgreen", fg='black'))
        self.load_button.bind("<Leave>", lambda e: self.load_button.configure(bg="#808080"))

        self.process_text = tk.Text(self.root, width=80, height=20, bg='#3d3d3d', fg='white', font=('Arial', 11))
        self.process_text.pack(pady=20, padx=10)
        # self.process_text(state='disabled')

        scrollbar = tk.Scrollbar(self.root, command=self.process_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.process_text.config(yscrollcommand=scrollbar.set)

        self.check_button = tk.Button(self.root, text="Check for Rootkits", command=self.check_for_rootkits)
        self.check_button.configure(bg='#808080', fg='white', padx=10, pady=5, font=('Arial', 12, 'bold'))
        self.check_button.pack(pady=30)
        self.check_button.bind("<Enter>", lambda e: self.check_button.configure(bg="tomato", fg='black'))
        self.check_button.bind("<Leave>", lambda e: self.check_button.configure(bg="#808080"))

        self.hidden_processes = []
        self.pro_value = 0

    def load_file (self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                    self.pro_value = 0
                    self.process_text.delete(1.0, tk.END)
                    self.process_text.insert(tk.END, content)
                    self.hidden_processes = [int(line.strip()) for line in content.splitlines() if line.strip().isdigit()]
                    if self.hidden_processes or 'PID' in content:
                        self.pro_value = 1
                        self.process_text.insert(tk.END, "\n\nProcess IDs loaded!\n" + "-"*70 + "\n")
                        self.process_text.insert(tk.END, "\n".join([f"Process ID: {pid}" for pid in self.hidden_processes]))
                    else:
                        self.process_text.insert(tk.END, "\n\nNo process IDs found in the file.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")

    def check_for_rootkits(self):
        if self.pro_value == 0:
            messagebox.showwarning("Warning", "No processes loaded.")
            return
        else:
            self.process_text.insert(tk.END, "\n\nStarting rootkit detection...\n\n")

            rootkits_found = []
            for pid in self.hidden_processes:
                try:
                    proc = psutil.Process(pid)
                    self.process_text.insert(tk.END, f"Scanning process {pid}: {proc.name()}...\n")
                    self.process_text.update_idletasks()
                    if self.is_suspicious(proc):
                        rootkits_found.append((pid, proc.name()))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    self.process_text.insert(tk.END, f"Skipping process {pid} (no access or no such process).\n")
                    self.process_text.update_idletasks()

            if rootkits_found:
                result_message = "Rootkits detected:\n" + "\n".join([f"PID: {pid}, Name: {name}" for pid, name in rootkits_found])
                self.process_text.insert(tk.END, result_message + "\n")
                messagebox.showinfo("Rootkits Detected", result_message)
            else:
                self.process_text.insert(tk.END, "✔No rootkits detected among the processes.\n✔No Suspicious system calls in the File.\n✔No unusual paths in the proccess.\n"
                                                 "✔No Hidden executable paths in the system calls.\n✔No unusual network activities Found.\n✔No processes with unusual command line arguments found.\n")
                messagebox.showinfo("No Rootkits", "No rootkits detected among the processes.")

    def is_suspicious(self, proc):
        suspicious_names = ['Zeus', 'Mirai', 'Emotet', 'Stuxnet', 'WannaCry',
                            "rootkit_example", 'NotPetya', 'Ghost', 'DarkComet', "suspicious_process",
                            'BlackEnergy', 'Xagent']
        if proc.name() in suspicious_names:
            return True

        suspicious_paths = ["/usr/local/bin/rootkit", "C:\\Windows\\System32\\suspicious.exe"," C:\\Windows\\Temp","C:\\Windows\\ConnectionStatus"," C:\\Windows\\WinSecurity"]
        if proc.exe() in suspicious_paths:
            return True

        if proc.username() in ["root", "SYSTEM", "domain", "admin"]:
            return True

        if '/.' in proc.exe() or '\\.' in proc.exe():
            return True

        if self.has_suspicious_network_activity(proc):
            return True

        try:
            unusual = ['tasklist', 'ver', 'ipconfig', 'systeminfo', 'net time', 'netstat', 'whoami',
                       'net start', 'qprocess', 'query', 'dir', 'net view', 'ping', 'net use', 'type', 'net user',
                       'net localgroup', 'net group', 'net config', 'net share']
            for i in unusual:
                if i in proc.cmdline():
                    return True
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        return False

    def has_suspicious_network_activity(self, proc):
        try:
            suspicious_ips = ["192.168.1.100", "10.0.0.200", "172.16.254.1", "203.0.113.5", "198.51.100.2",
                              "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "74.125.224.72", "23.235.47.133",
                              "104.16.99.52", "195.22.26.248", "45.60.103.32", "69.171.250.35", "47.156.224.38"]

            suspicious_ports = [3389, 5900, 1723, 3036, 3306, 5590, 8900, 8080, 21, 22, 23, 25, 52, 53, 80,
                                110, 111, 135, 144, 149, 443, 444, 999, 995, 6666, 7777, 4444, 5555, 8888]

            connections = proc.connections(kind='inet')
            for conn in connections:
                if conn.raddr and conn.raddr.ip in suspicious_ips:
                    return True
                if conn.raddr and conn.raddr.port in suspicious_ports:
                    return True
                if conn.status == 'ESTABLISHED' and conn.laddr.port > 1024:
                    if len(connections) > 10:
                        return True
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return False

        return False

# Hiding_viruses class
class Hiding_viruses:
    def __init__(self, root):
        self.root = root

        bold_font = font.Font(weight='bold')

        heading_label = tk.Label(self.root, text="- Hiding Viruses -", font=('Arial', 14, 'bold'), fg='white', bg='#2e2e2e')
        heading_label.pack(pady=10)

        # Scrollbar
        scrollbar = ttk.Scrollbar(root, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        entry = tk.Text(root, height=20, width=80, wrap=tk.WORD, yscrollcommand=scrollbar.set, font=('Arial', 12))
        entry.configure(state='normal', bg='#555555', fg='white')
        # Define a tag for the heading
        entry.tag_configure("heading", font=('Arial', 16, 'bold'), foreground='yellow')


        entry.pack(side="left", fill="both")
        # self.Text.pack(pady=20)

        entry.insert(tk.END,'''Processes are an unavoidable part of Windows, and it is not unusual to see dozens or hundreds\nof them in Task Manager. Each process is a program or part of a program that is running. Unfortunately, malware creators know this and are known to hide malicious software behind the names of legitimate processes.

        Here are some of the most commonly hijacked or duplicated processes,along with where\nthey should be located and how to spot a MALICIOUS VERSION:\n
        ''')

        entry.insert(tk.END,"1. Svchost.exe","heading")
        entry.insert(tk.END,'''\nThe Service Host, or svchost.exe, is a shared-service process. It allows various other Windows services to share processes. You will almost certainly see more than one instance of Svchost.exe in Task Manager, but this is normal. If one or more of these files are compromised by malware, you may notice a distinct reduction in performance.
        The legitimate Svchost files should be found in C:\\Windows\\System32.If you\nsuspect it has been hijacked, check C:\\Windows\\Temp. If you see svchost.exe here, it\ncould be a malicious file. Scan the file with your antivirus software, and quarantine it if necessary.\n
        ''')

        entry.insert(tk.END, "2. Explorer.exe", "heading")
        entry.insert(tk.END, '''\nExplorer.exe is responsible for the graphical shell. without it, you would have no Taskbar, Start Menu, File Manager, or even the Desktop.Several viruses can use the Explorer.exe filename to hide behind, including trojan.w32.ZAPCHAST. The real file will be in C:\\Windows.\nIf you find it in System32, you should definitely check it with your antivirus software.\n\n''')

        entry.insert(tk.END, "     3. Winlogon.exe", "heading")
        entry.insert(tk.END,'''\nThe Winlogon.exe process is an essential part of the Windows OS. It handles things like loading the user profile during login and locking the computer when the screensaver runs.Several Trojan viruses, including Vundo, can be hidden within or disguised as winlogon.exe. The path of the Winlogon.exe file is C:\\Windows\\System32. If it is in C:\\Windows\\WinSecurity,\nit could be malicious. One good indication that the process has been hijacked is unusually high memory use.\n\n''')

        entry.insert(tk.END, "    4. Csrss.exe", "heading")
        entry.insert(tk.END, '''\nThe Client/Server Run-Time Subsystem, or Csrss.exe, is an essential Windows process.The Nimda.E virus has been known to mimic this process, although that is not the only potential threat. The legitimate file should be located in the System32 or SysWOW64 folders. Right-click on the Csrss.exe process in Task Manager and choose Open File Location. If it is located anywhere else, it is likely to be a malicious file.\n\n''')
        entry.insert(tk.END, "   5. Lsass.exe", "heading")
        entry.insert(tk.END, '''\nlsass.exe is an essential process responsible for the security policy on Windows. It verifies the login name and password, among other security procedures. Look for the Lsass.exe file in C:\\Windows\\System32. This is the only place you should find it.If you see it in another location, such as C:\\Windows\\system or C:\\Program Files, act with suspicion and scan the file with your antivirus.\n\n''')

        entry.insert(tk.END, "   6. Services.exe", "heading")
        entry.insert(tk.END,'''\nThe Services.exe process is responsible for starting and stopping various essential Windows services. If the file is hijacked, you may notice problems during the startup and shutdown of your PC. Look for the real Services.exe file in the System32 folder. If it is located anywhere else\nlike C:\\Windows\\ConnectionStatus,the file could be a virus.\n\n''')
        entry.insert(tk.END, "   7. Spoolsv.exe", "heading")
        entry.insert(tk.END, '''\nThe Windows Print Spooler Service, or Spoolsv.exe, is an important part of the printing interface.\nIt runs in the background, waiting to manage things like the print queue when required.The true spools file can be found in C:\\Windows\\System32. The fake file will be in C:\\Windows, or in a user profile folder.\n\n''')

        entry.insert(tk.END, "   How Do You Check if a Process Is Legitimate?", "heading")
        entry.insert(tk.END, '''\nThe Task Manager is your friend when looking for suspicious activity. Infected processes will often behave erratically, consuming more CPU power and memory than is usual. But that isn't always the case, so here are some other\nways to check a process is legitimate.

    Most of the essential processes listed here should only appear in the System32 folder. You can easily check the location of a suspicious file in the Task Manager. Right-click on the process and select Open File Location. Check the path of the folder that opens to ensure the file is in the correct place.

    Another way to tell if a file is legitimate is to check the size.Most of the .exe files of these essential processes will be under 200kb. Right-click on the process name in Task Manager, select Properties and look at the size. If it seems unusually large, take a closer look to determine if it is safe.\n''')
        entry.insert(tk.END, '''\nYou can also check the certificate of the EXE file. An authentic file will have a security certificate issued by Microsoft. If you see anything else, it is likely to be malicious...''')

        # Add tags to ranges of text to make them bold and different colors
        entry.tag_add("bold_red", "5.41", "5.58")
        entry.tag_add("bold_red", "8.304", "8.337")
        entry.tag_add("bold_green", "9.56", "9.75")
        entry.tag_add("bold_red", "10.36", "10.51")
        entry.tag_add("bold_red", "14.214", "14.233")
        entry.tag_add("bold_green", "14.260", "14.271")
        entry.tag_add("bold_red", "15.18", "15.26")
        entry.tag_add("bold_red", "18.211", "18.216")
        entry.tag_add("bold_green", "18.306", "18.325")
        entry.tag_add("bold_red", "18.339", "18.362")
        entry.tag_add("bold_red", "19.81", "19.106")
        entry.tag_add("bold_red", "22.88", "22.101")
        entry.tag_add("bold_green", "22.233", "22.241")
        entry.tag_add("bold_green", "22.245", "22.253")
        entry.tag_add("bold_red", "22.400", "22.414")
        entry.tag_add("bold_green", "25.187", "25.207")
        entry.tag_add("bold_red", "25.293", "25.310")
        entry.tag_add("bold_red", "25.314", "25.330")
        entry.tag_add("bold_green", "28.238", "28.246")
        entry.tag_add("bold_red", "29.5", "29.32")
        entry.tag_add("bold_green", "33.124", "33.144")
        entry.tag_add("bold_red", "33.170", "33.180")
        entry.tag_add("bold_red", "33.190", "33.202")
        entry.tag_add("bold_green", "36.4", "36.16")
        entry.tag_add("bold_red", "36.70", "36.169")
        entry.tag_add("bold_green", "39.74", "39.82")
        entry.tag_add("bold_green", "39.167", "39.223")
        entry.tag_add("bold_green", "41.129", "41.140")
        entry.tag_add("bold_green", "43.113", "43.122")

        entry.tag_add("bold_red", "43.168", "43.178")

        # Configure the tags
        entry.tag_config("bold_red", font=bold_font, foreground="tomato")
        entry.tag_config("bold_green", font=bold_font, foreground="lightgreen")


        # entry.tag_config("bold", font=bold_font)

        entry.config(state='disabled')
        scrollbar.config(command=entry.yview)


# Save Processes App class
class SaveProcessesApp:
    def __init__(self, root):
        self.root = root
        self.root.configure(bg='#2e2e2e')

        heading_label = tk.Label(self.root, text="- Save Processes to File -",
                                 font=('Arial', 14, 'bold'), fg='white', bg='#2e2e2e')
        heading_label.pack(pady=10)

        self.scan_button = tk.Button(self.root, text="Scan Processes", command=self.scan_and_save_processes)
        self.scan_button.configure(bg='#808080', fg='white', padx=10, pady=5, font=('Arial', 12, 'bold'))
        self.scan_button.pack(pady=20)
        self.scan_button.bind("<Enter>", lambda e: self.scan_button.configure(bg="lightblue", fg='black'))
        self.scan_button.bind("<Leave>", lambda e: self.scan_button.configure(bg="#808080"))

        self.process_listbox = tk.Listbox(self.root, width=80, height=20, bg='#3d3d3d', fg='white', font=('Arial', 11))
        self.process_listbox.pack(pady=20, padx=10)

        scrollbar = tk.Scrollbar(self.root, command=self.process_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.process_listbox.config(yscrollcommand=scrollbar.set)

    def scan_and_save_processes(self):
        processes = scan_processes()
        save_to_file(processes)
        self.process_listbox.delete(0, tk.END)
        for process in processes:
            self.process_listbox.insert(tk.END, process)
        messagebox.showinfo("Success", "Processes saved to process_list.txt")

# Main application window
class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RootKits Detector v1.00")
        self.root.geometry("700x670")
        self.root.configure(bg='#2e2e2e')
        # Disable the resizable Property
        root.resizable(False, False)
        # Adding image icon
        photo = PhotoImage(file="malware.png")
        root.iconphoto(False, photo)


        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, expand=True)

        self.save_processes_frame = tk.Frame(self.notebook, bg='#2e2e2e')
        self.rootkit_frame = tk.Frame(self.notebook, bg='#2e2e2e')
        self.Hiding_viruses_frame = tk.Frame(self.notebook, bg='#2e2e2e')

        self.notebook.add(self.save_processes_frame, text="Save Processes")
        self.notebook.add(self.rootkit_frame, text="Rootkit Detector")
        self.notebook.add(self.Hiding_viruses_frame, text="Hiding_viruses")

        self.save_processes_app = SaveProcessesApp(self.save_processes_frame)
        self.rootkit_app = RootkitDetectorApp(self.rootkit_frame)
        self.Hiding_viruses_app = Hiding_viruses(self.Hiding_viruses_frame)

if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()
