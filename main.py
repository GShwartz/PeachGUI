import tkinter

from PIL import Image, ImageTk
from datetime import datetime
from termcolor import colored
from threading import Thread
from colorama import init
import os.path
import socket
import psutil
import time
import sys

# GUI
from tkinter import messagebox
from tkinter import *
from tkinter import ttk
import tkinter as tk

# Local Modules
from Modules import screenshot
from Modules import tasks
from Modules import vital_signs
from Modules import sysinfo
from Modules import freestyle

init()


class App(tk.Tk):
    clients = {}
    connections = {}
    connHistory = []
    ips = []
    targets = []

    # Temp dict to hold connected station's ID# & IP
    temp = {}

    port = 55400
    ttl = 5
    hostname = socket.gethostname()
    serverIP = str(socket.gethostbyname(hostname))
    path = r'c:\Peach'
    log_path = fr'{path}\server_log.txt'

    def __init__(self):
        super().__init__()
        # ======== Server Config ==========
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.serverIP, self.port))
        self.server.listen()

        # Create local app DIR
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        # Run Listener Thread
        listenerThread = Thread(target=self.run, name="Listener Thread")
        listenerThread.daemon = True
        listenerThread.start()

        # ======== GUI Config ===========
        self.title("Peach")
        self.height = self.winfo_height()
        self.width = self.winfo_width()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # =-=-=-=-=-=-= FRAMES =-=-=-=-=-=-=-=
        # Main Window Frames
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar Frame
        self.sidebar_frame = Frame(self, width=150, background="RoyalBlue4")
        self.sidebar_frame.grid(row=0, column=0, sticky="nswe")
        self.sidebar_frame.rowconfigure(5, weight=10)

        # Main Frame
        self.main_frame = Frame(self, background="ghost white", relief="solid")
        self.main_frame.grid(row=0, column=1, sticky="nswe", padx=5)
        self.main_frame.rowconfigure(5, weight=1)

        # Main Frame top bar - shows server information
        self.main_frame_top = Frame(self.main_frame, relief='flat', height=30)
        self.main_frame_top.grid(row=0, column=1, sticky="nwes")

        # Main frame top bar LabelFrame
        self.top_bar_label = LabelFrame(self.main_frame, text="Server Information", relief='solid')
        self.top_bar_label.grid(row=0, column=1, sticky='news')

        # Main Frame Table space
        self.main_frame_table = Frame(self.main_frame, relief='flat')
        self.main_frame_table.grid(row=1, column=1, sticky="news", pady=5)

        # Controller Buttons LabelFrame
        self.controller_btns = LabelFrame(self.main_frame, text="Controller", relief='solid', height=50)
        self.controller_btns.grid(row=2, column=0, columnspan=5, sticky="ews", pady=5)

        # =-=-=-=-=-=-= BUTTONS =-=-=-=-=-=-=-=
        # Sidebar Buttons
        # Refresh Button
        self.refresh_bt = tk.Button(self.sidebar_frame,
                                    text="Refresh", width=15, pady=10,
                                    command=lambda: self.refresh())
        self.refresh_bt.grid(row=0, sticky="nwes")

        # Update Clients
        self.btn_update_clients = tk.Button(self.sidebar_frame,
                                            text="Update Clients", width=15, pady=10,
                                            command="")
        self.btn_update_clients.grid(row=2, sticky="nwes")

        # Create Connected Table inside Main Frame when show connected btn pressed
        self.table_frame = ttk.LabelFrame(self.main_frame_table, text="Connected Stations")
        self.table_frame.grid(row=0, sticky="new", pady=5)

        # Create a Table for connected stations
        self.table = ttk.Treeview(self.table_frame,
                                  columns=("id", "MAC Address",
                                           "IP Address", "Station Name",
                                           "Logged User", "Client Version"),
                                  show="headings", height=10, selectmode='browse')
        self.table.grid(row=0, pady=10)

        # Create Scrollbar
        self.table_sb = Scrollbar(self.table_frame, orient=VERTICAL)
        self.table_sb.grid(row=0, sticky="wns")

        # Columns & Headings config
        self.table.column("#1", anchor=CENTER)
        self.table.heading("#1", text="ID")
        self.table.column("#2", anchor=CENTER)
        self.table.heading("#2", text="MAC")
        self.table.column("#3", anchor=CENTER)
        self.table.heading("#3", text="IP")
        self.table.column("#4", anchor=CENTER)
        self.table.heading("#4", text="Station Name")
        self.table.column("#5", anchor=CENTER)
        self.table.heading("#5", text="Logged User")
        self.table.column("#6", anchor=CENTER)
        self.table.heading("#6", text="Client Version")
        self.table.bind("<Button 1>", self.selectItem)

        # Style Table
        self.style = ttk.Style()
        self.style.configure("Treeview", rowheight=20)
        self.style.map("Treeview")

        self.server_information()
        self.show_available_connections()

    # Refresh server info & connected stations table with vital signs
    def refresh(self):
        self.tmp_availables = []
        self.vital_signs()
        self.server_information()
        self.show_available_connections()

    # ======== GUI Section =========
    # Display Server Information Thread
    def dsi_thread(self):
        # Display Server Information
        infoThread = Thread(target=self.server_information, name="ServerInfo")
        infoThread.daemon = True
        infoThread.start()

    # Display Server Information
    def server_information(self):
        self.logIt_thread(self.log_path, msg=f'Running show server information...')
        last_reboot = psutil.boot_time()
        data = {
            'Server_IP': self.serverIP,
            'Server_Port': self.port,
            'Last_Boot': datetime.fromtimestamp(last_reboot).replace(microsecond=0),
            'Connected_Stations': len(self.targets)
        }

        label = Label(self.top_bar_label, text=f"\t\t\t\t\tServer IP: {self.serverIP}\t\tServer Port: {self.port}\t\t"
                                               f"Last Boot: {datetime.fromtimestamp(last_reboot).replace(microsecond=0)}\t\t"
                                               f"Connected Stations: {len(self.targets)}", anchor=CENTER)
        label.grid(row=0, sticky='w')

        return data

    # Show Available Connections Thread
    def sac_thread(self):
        self.sacThread = Thread(target=self.show_available_connections,
                                name="Show Available Connections Thread")
        self.sacThread.daemon = True
        self.sacThread.start()

    # Show Available Connections
    def show_available_connections(self) -> None:
        if len(self.ips) == 0 and len(self.targets) == 0:
            self.logIt_thread(self.log_path, msg=f'No connected Stations')
            print(f"[{colored('*', 'cyan')}]No connected stations.\n")

        self.logIt_thread(self.log_path, msg=f'Running show_available_connections()...')

        def make_tmp():
            count = 0
            for conKey, macValue in self.clients.items():
                for macKey, ipValue in macValue.items():
                    for ipKey, identValue in ipValue.items():
                        for con in self.targets:
                            if con == conKey:
                                for identKey, userValue in identValue.items():
                                    for userV, clientVer in userValue.items():
                                        if (count, macKey, ipKey, identKey, userValue) in self.tmp_availables:
                                            continue

                                self.tmp_availables.append((count, macKey, ipKey, identKey, userV, clientVer))
                count += 1

            self.logIt_thread(self.log_path, msg=f'Available list created.')

        def extract():
            for item in self.tmp_availables:
                for conKey, ipValue in self.clients.items():
                    for macKey, ipVal in ipValue.items():
                        for ipKey, identVal in ipVal.items():
                            if item[2] == ipKey:
                                session = item[0]
                                stationMAC = item[1]
                                stationIP = item[2]
                                stationName = item[3]
                                loggedUser = item[4]
                                clientVersion = item[5]

                                # Show results in GUI table
                                self.table.insert('', 'end', values=(session, stationMAC, stationIP,
                                                                     stationName, loggedUser, clientVersion))

                                print(f"Session [{colored(f'{session}', 'cyan')}] | "
                                      f"Station MAC: {colored(f'{stationMAC}', 'green')} | "
                                      f"Station IP: {colored(f'{stationIP}', 'green')} | "
                                      f"Station Name: {colored(f'{stationName}', 'green')} | "
                                      f"Logged User: {colored(f'{loggedUser}', 'green')} | "
                                      f"Client Version: {colored(clientVersion, 'green')}")

            self.logIt_thread(self.log_path, msg=f'Extraction completed.')

        # Cleaning availables list
        self.logIt_thread(self.log_path, msg=f'Cleaning availables list...')
        self.tmp_availables = []

        # Clear previous entries in GUI table
        self.table.delete(*self.table.get_children())

        print(f"[{colored('*', 'cyan')}] {colored('Available Connections', 'green')} [{colored('*', 'cyan')}]")
        print(f"{colored('=', 'yellow') * 29}")

        self.logIt_thread(self.log_path, msg=f'Creating available list...')
        make_tmp()

        self.logIt_thread(self.log_path,
                          msg=f'Extracting: Session | Station IP | Station Name | Logged User '
                              f'from clients list...')
        extract()

    # Close App Window
    def on_closing(self, event=0):
        self.destroy()

    # ======== Server Section =========
    def reset(self) -> None:
        self.__init__()
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.serverIp, self.serverPort))
        self.server.listen()

    def bytes_to_number(self, b: int) -> int:
        self.logIt_thread(self.log_path, msg=f'Running bytes_to_number({b})...')
        dt = get_date()
        res = 0
        for i in range(4):
            res += b[i] << (i * 8)
        return res

    def get_date(self) -> str:
        d = datetime.now().replace(microsecond=0)
        dt = str(d.strftime("%m/%d/%Y %H:%M:%S"))

        return dt

    def logIt(self, logfile=None, debug=None, msg='') -> bool:
        dt = self.get_date()
        if debug:
            print(f"{dt}: {msg}")

        if logfile is not None:
            try:
                if not os.path.exists(logfile):
                    with open(logfile, 'w') as lf:
                        lf.write(f"{dt}: {msg}\n")

                    return True

                else:
                    with open(logfile, 'a') as lf:
                        lf.write(f"{dt}: {msg}\n")

                    return True

            except FileExistsError:
                pass

    def logIt_thread(self, log_path=None, debug=False, msg='') -> None:
        self.logit_thread = Thread(target=self.logIt, args=(log_path, debug, msg), name="Log Thread")
        self.logit_thread.start()

    def run(self) -> None:
        self.logIt_thread(self.log_path, msg=f'Running run()...')
        self.logIt_thread(self.log_path, msg=f'Calling connect() in new thread...')
        self.connectThread = Thread(target=self.connect, daemon=True, name=f"Connect Thread")
        self.connectThread.start()

        self.logIt_thread(self.log_path, msg=f'Adding thread to threads list...')
        self.logIt_thread(self.log_path, msg=f'Thread added to threads list.')

    def connect(self) -> None:
        def get_mac_address() -> str:
            self.logIt_thread(self.log_path, msg=f'Waiting for MAC address from {self.ip}...')
            self.mac = self.conn.recv(1024).decode()
            self.logIt_thread(self.log_path, msg=f'MAC Address: {self.mac}')

            self.logIt_thread(self.log_path, msg=f'Sending confirmation to {self.ip}...')
            self.conn.send('OK'.encode())
            self.logIt_thread(self.log_path, msg=f'Send completed.')

            return self.mac

        def get_hostname() -> str:
            self.logIt_thread(self.log_path, msg=f'Waiting for remote station name...')
            self.ident = self.conn.recv(1024).decode()
            self.logIt_thread(self.log_path, msg=f'Remote station name: {self.ident}')

            self.logIt_thread(self.log_path, msg=f'Sending Confirmation to {self.ip}...')
            self.conn.send('OK'.encode())
            self.logIt_thread(self.log_path, msg=f'Send completed.')

            return self.ident

        def get_user() -> str:
            self.logIt_thread(self.log_path, msg=f'Waiting for remote station current logged user...')
            self.user = self.conn.recv(1024).decode()
            self.logIt_thread(self.log_path, msg=f'Remote station user: {self.user}')

            self.logIt_thread(self.log_path, msg=f'Sending Confirmation to {self.ip}...')
            self.conn.send('OK'.encode())
            self.logIt_thread(self.log_path, msg=f'Send completed.')

            return self.user

        def get_client_version() -> str:
            self.logIt_thread(self.log_path, msg=f'Waiting for client version...')
            self.client_version = self.conn.recv(1024).decode()
            self.logIt_thread(self.log_path, msg=f'Client version: {self.client_version}')

            self.logIt_thread(self.log_path, msg=f'Sending confirmation to {self.ip}...')
            self.conn.send('OK'.encode())
            self.logIt_thread(self.log_path, msg=f'Send completed.')

            return self.client_version

        self.logIt_thread(self.log_path, msg=f'Running connect()...')
        while True:
            self.logIt_thread(self.log_path, msg=f'Accepting connections...')
            self.conn, (self.ip, self.port) = self.server.accept()
            self.logIt_thread(self.log_path, msg=f'Connection from {self.ip} accepted.')

            try:
                # Get MAC Address
                self.client_mac = get_mac_address()

                # Get Remote Computer's Name
                get_hostname()

                # Get Current User
                get_user()

                # Get Client Version
                get_client_version()

            except (WindowsError, socket.error) as e:
                self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')
                return  # Restart The Loop

            # Update Thread Dict and Connection Lists
            if self.conn not in self.targets and self.ip not in self.ips:
                self.logIt_thread(self.log_path, msg=f'New Connection!')

                # Add Socket Connection To Targets list
                self.logIt_thread(self.log_path, msg=f'Adding {self.conn} to targets list...')
                self.targets.append(self.conn)
                self.logIt_thread(self.log_path, msg=f'targets list updated.')

                # Add IP Address Connection To IPs list
                self.logIt_thread(self.log_path, msg=f'Adding {self.ip} to ips list...')
                self.ips.append(self.ip)
                self.logIt_thread(self.log_path, msg=f'ips list updated.')

                # Set Temp Dict To Update Live Connections List
                self.logIt_thread(self.log_path, msg=f'Adding {self.conn} | {self.ip} to temp live connections dict...')
                self.temp_connection = {self.conn: self.ip}
                self.logIt_thread(self.log_path, msg=f'Temp connections dict updated.')

                # Add Temp Dict To Connections List
                self.logIt_thread(self.log_path, msg=f'Updating connections list...')
                self.connections.update(self.temp_connection)
                self.logIt_thread(self.log_path, msg=f'Connections list updated.')

                # Set Temp Idents Dict For Idents
                self.logIt_thread(self.log_path, msg=f'Creating dict to hold ident details...')
                self.temp_ident = {self.conn: {
                    self.client_mac: {
                        self.ip: {
                            self.ident: {
                                self.user: self.client_version}}}}}

                self.logIt_thread(self.log_path, msg=f'Dict created: {self.temp_ident}')

                # Add Temp Idents Dict To Idents Dict
                self.logIt_thread(self.log_path, msg=f'Updating live clients list...')
                self.clients.update(self.temp_ident)
                self.logIt_thread(self.log_path, msg=f'Live clients list updated.')

            # Create a Dict of Connection, IP, Computer Name, Date & Time
            self.logIt_thread(self.log_path, msg=f'Fetching current date & time...')
            dt = get_date()
            self.logIt_thread(self.log_path, msg=f'Creating a connection dict...')
            self.temp_connection_record = {self.conn: {self.ip: {self.ident: {self.user: dt}}}}
            self.logIt_thread(self.log_path, msg=f'Connection dict created: {self.temp_connection_record}')

            # Add Connection to Connection History
            self.logIt_thread(self.log_path, msg=f'Adding connection to connection history...')
            self.connHistory.append(self.temp_connection_record)
            self.logIt_thread(self.log_path, msg=f'Connection added to connection history.')

            self.logIt_thread(self.log_path, msg=f'Calling self.welcome_message() condition...')
            if self.welcome_message():
                continue

    def welcome_message(self) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running welcome_message()...')

        # Send Welcome Message
        try:
            self.welcome = "Connection Established!"
            self.logIt_thread(self.log_path, msg=f'Sending welcome message...')
            self.conn.send(f"@Server: {self.welcome}".encode())
            self.logIt_thread(self.log_path, msg=f'{self.welcome} sent to {self.ident}.')

            return True

        except (WindowsError, socket.error) as e:
            self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')
            if self.conn in self.targets and self.ip in self.ips:
                self.logIt_thread(self.log_path, msg=f'Removing {self.conn} from self.targets...')
                self.targets.remove(self.conn)

                self.logIt_thread(self.log_path, msg=f'Removing {self.ip} from self.ips list...')
                self.ips.remove(self.ip)

                self.logIt_thread(self.log_path, msg=f'Deleting {self.conn} from self.connections.')
                del self.connections[self.conn]

                self.logIt_thread(self.log_path, msg=f'Deleting {self.conn} from self.clients...')
                del self.clients[self.conn]

                self.logIt_thread(self.log_path, msg=f'[V]Connection removed from lists.')

                return False

    def connection_history(self) -> None:
        self.logIt_thread(self.log_path, msg=f'Running connection_history()...')
        print("\t\t" + f"{colored('=', 'blue')}" * 20, f"=> {colored('CONNECTION HISTORY', 'red')} <=",
              f"{colored('=', 'blue')}" * 20)
        c = 1  # Initiate Counter for Connection Number
        try:
            # Iterate Through Connection History List Items
            self.logIt_thread(self.log_path, msg=f'Iterating self.connHistory...')
            for connection in self.connHistory:
                for conKey, ipValue in connection.items():
                    for ipKey, identValue in ipValue.items():
                        for identKey, userValue in identValue.items():
                            for userKey, timeValue in userValue.items():
                                print(
                                    f"[{colored(str(c), 'green')}]{colored('IP', 'cyan')}: {ipKey} | "
                                    f"{colored('Station Name', 'cyan')}: {identKey} | "
                                    f"{colored('User', 'cyan')}: {userKey} | "
                                    f"{colored('Time', 'cyan')}: {str(timeValue).replace('|', ':')}")
                    c += 1

        # Break If Client Lost Connection
        except (KeyError, socket.error, ConnectionResetError) as e:
            self.logIt_thread(self.log_path, msg=f'Iteration Error: {e}')
            return

    def vital_signs(self) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running vital_signs()...')
        if len(self.targets) == 0:
            messagebox.showinfo("Refresh", "No Connected Stations.")
            return

        sure = messagebox.askquestion("Start Vitals Check", "This will start the vitals check. Are you sure?")
        if sure:
            temp = self.clients
            callback = 'yes'
            i = 0

            self.logIt_thread(self.log_path, msg=f'Iterating Through Temp Connected Sockets List...')
            for t in self.targets:
                try:
                    self.logIt_thread(self.log_path, msg=f'Sending "alive" to {t}...')
                    t.send('alive'.encode())
                    self.logIt_thread(self.log_path, msg=f'Send completed.')

                    self.logIt_thread(self.log_path, msg=f'Waiting for response from {t}...')
                    ans = t.recv(1024).decode()
                    self.logIt_thread(self.log_path, msg=f'Response from {t}: {ans}.')

                    self.logIt_thread(self.log_path, msg=f'Waiting for client version from {t}...')
                    ver = t.recv(1024).decode()
                    self.logIt_thread(self.log_path, msg=f'Response from {t}: {ver}.')

                except socket.error:
                    self.remove_lost_connection(t, self.ips[i])
                    break

                if str(ans) == str(callback):
                    try:
                        for conKey, ipValue in self.clients.items():
                            for ipKey, identValue in ipValue.items():
                                if t == conKey:
                                    for name, version in identValue.items():
                                        for v, v1 in version.items():
                                            for n, ver in v1.items():
                                                print(
                                                    f"[{colored('V', 'green')}]{self.ips[i]} | {v} | Version: {ver}")
                                                i += 1
                                                time.sleep(0.5)

                    except (IndexError, RuntimeError):
                        pass

                else:
                    for conKey, macValue in self.clients.items():
                        if conKey == con:
                            for macKey, ipVal in macValue.items():
                                for ipKey, identValue in ipVal.items():
                                    if ipKey == self.ips[i]:
                                        print(ipKey)
                                        self.remove_lost_connection(conKey, ipKey)

            self.logIt_thread(self.log_path, msg=f'=== End of vital_signs() ===')
            print(f"\n[{colored('*', 'green')}]Vital Signs Process completed.\n")

        else:
            self.logIt_thread(self.log_path, msg=f'Closing vital_signs()...')
            return False

    def show_shell_commands(self, ip: str) -> None:
        self.logIt_thread(self.log_path, msg=f'Running show_shell_commands()...')
        self.logIt_thread(self.log_path, msg=f'Displaying headline...')
        print("\t\t" + f"{colored('=', 'blue')}" * 20, f"=> {colored('REMOTE CONTROL', 'red')} <=",
              f"{colored('=', 'blue')}" * 20)

        self.logIt_thread(self.log_path, msg=f'Displaying Station IP | Station Name | Logged User in headline...')
        for conKey, ipValue in self.clients.items():
            for ipKey, userValue in ipValue.items():
                if ipKey == ip:
                    for item in self.tmp_availables:
                        if item[1] == ip:
                            for identKey, timeValue in userValue.items():
                                loggedUser = item[3]
                                clientVersion = item[4]
                                print("\t" + f"IP: {colored(f'{ipKey}', 'green')} | "
                                             f"Station Name: {colored(f'{identKey}', 'green')} | "
                                             f"Logged User: {colored(f'{loggedUser}', 'green')} | "
                                             f"Client Version: {colored(clientVersion, 'green')}")

        print("\t\t" + f"{colored('=', 'yellow')}" * 62 + "\n")

        self.logIt_thread(self.log_path, msg=f'Displaying shell commands menu...')
        print(f"\t\t[{colored('1', 'cyan')}]Screenshot          \t\t---------------> "
              f"Capture screenshot.")
        print(f"\t\t[{colored('2', 'cyan')}]System Info         \t\t---------------> "
              f"Show Station's System Information")
        print(f"\t\t[{colored('3', 'cyan')}]Last Restart Time   \t\t---------------> "
              f"Show remote station's last restart time")
        print(f"\t\t[{colored('4', 'cyan')}]Anydesk             \t\t---------------> "
              f"Start Anydesk")
        print(f"\t\t[{colored('5', 'cyan')}]Tasks               \t\t---------------> "
              f"Show remote station's running tasks")
        print(f"\t\t[{colored('6', 'cyan')}]Restart             \t\t---------------> "
              f"Restart remote station")
        print(f"\t\t[{colored('7', 'cyan')}]CLS                 \t\t---------------> "
              f"Clear Screen")
        print(f"\n\t\t[{colored('8', 'red')}]Back                \t\t---------------> "
              f"Back to Control Center \n")

        self.logIt_thread(self.log_path, msg=f'=== End of show_shell_commands() ===')

    def restart(self, con: str, ip: str, sname: str) -> bool:
        # Display MessageBox on screen
        self.sure = messagebox.askyesno(f"Restart for: {ip} | {sname}", f"Are you sure you want to restart {sname}?\t")
        if self.sure:
            try:
                self.logIt_thread(self.log_path, msg=f'Sending restart command to client...')
                con.send('restart'.encode())
                self.remove_lost_connection(con, ip)
                return True

            except (RuntimeError, WindowsError, socket.error) as e:
                self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')
                print(f"[{colored('!', 'red')}]Client lost connection.")

                self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                self.remove_lost_connection(con, ip)
                return False

        else:
            return False

    def last_restart(self, con: str, ip: str, sname: str) -> bool:
        try:
            self.logIt_thread(self.log_path, debug=False, msg=f'Sending lr command to client...')
            con.send('lr'.encode())
            self.logIt_thread(self.log_path, debug=False, msg=f'Send Completed.')

            self.logIt_thread(self.log_path, debug=False, msg=f'Waiting for response from client...')
            msg = con.recv(4096).decode()
            self.logIt_thread(self.log_path, debug=False, msg=f'Client response: {msg}')

            # Display MessageBox on screen
            messagebox.showinfo(f"Last Restart for: {ip} | {sname}", f"\t{msg.split('|')[1][15:]}\t\t\t")

            return True

        except (WindowsError, socket.error, ConnectionResetError) as e:
            self.logIt_thread(self.log_path, debug=False, msg=f'Connection Error: {e}.')
            print(f"[{colored('!', 'red')}]Client lost connection.")
            try:
                self.logIt_thread(self.log_path, debug=False,
                                  msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                self.remove_lost_connection(con, ip)
                return False

            except RuntimeError as e:
                self.logIt_thread(self.log_path, debug=True, msg=f'Runtime Error: {e}.')
                return False

    def anydesk(self, con: str, ip: str) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running anydesk({con}, {ip})...')
        try:
            self.logIt_thread(self.log_path, msg=f'Sending anydesk command to {con}...')
            con.send('anydesk'.encode())
            self.logIt_thread(self.log_path, msg=f'Send Completed.')

            self.logIt_thread(self.log_path, msg=f'Waiting for response from client...')
            msg = con.recv(1024).decode()
            self.logIt_thread(self.log_path, msg=f'Client response: {msg}.')

            if "OK" not in msg:
                self.logIt_thread(self.log_path, msg=f'Printing msg from client...')
                print(msg)
                while True:
                    try:
                        install_anydesk = messagebox.askquestion("Install Anydesk",
                                                                 "Anydesk isn't installed on the remote machine. do you with to install?")
                        # install_input = str(input("Install Anydesk [Y/n]? "))

                    except ValueError:
                        print(f"[{colored('!', 'red')}]Wrong input.")
                        continue

                    if install_anydesk:
                        print("Installing anydesk...")
                        self.logIt_thread(self.log_path, msg=f'Sending install command to {con}...')
                        con.send('y'.encode())
                        self.logIt_thread(self.log_path, msg=f'Send Completed.')

                        while True:
                            self.logIt_thread(self.log_path, msg=f'Waiting for response from client...')
                            msg = con.recv(1024).decode()
                            self.logIt_thread(self.log_path, msg=f'Client response: {msg}.')

                            if "OK" not in str(msg):
                                print(msg)
                                continue

                            else:
                                print(msg)
                                return False

                        return True

                    else:
                        self.logIt_thread(self.log_path, msg=f'Sending cancel command to {con}...')
                        con.send('n'.encode())
                        self.logIt_thread(self.log_path, msg=f'Send Completed.')
                        break

        except (WindowsError, ConnectionError, socket.error) as e:
            self.logIt_thread(self.log_path, msg=f'Connection Error: {e}.')
            print(f"[{colored('!', 'red')}]Client lost connection.")
            try:
                self.logIt_thread(self.log_path, debug=True,
                                  msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                self.remove_lost_connection(con, ip)
                return False

            except RuntimeError as e:
                self.logIt_thread(self.log_path, debug=True, msg=f'Runtime Error: {e}.')
                return False

    def screenshot(self, con: str, ip: str) -> None:
        try:
            print(f"[{colored('*', 'cyan')}]Fetching screenshot...")
            self.logIt_thread(self.log_path, msg=f'Sending screen command to client...')
            con.send('screen'.encode())
            self.logIt_thread(self.log_path, msg=f'Send Completed.')

            self.logIt_thread(self.log_path, msg=f'Calling Module: '
                                                 f'screenshot({con, self.path, self.tmp_availables, self.clients})...')

            scrnshot = screenshot.Screenshot(con, self.path, self.tmp_availables,
                                             self.clients, self.log_path, self.targets)

            self.logIt_thread(self.log_path, msg=f'Calling screenshot.recv_file()...')
            scrnshot.recv_file(ip)

        except (WindowsError, socket.error, ConnectionResetError) as e:
            self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')
            print(f"[{colored('!', 'red')}]Client lost connection.")

            self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip}...)')
            self.remove_lost_connection(con, ip)

    def sysinfo(self, con: str, ip: str):
        try:
            self.logIt_thread(self.log_path, msg=f'Initializing Module: sysinfo...')
            sinfo = sysinfo.Sysinfo(con, self.ttl, self.path, self.tmp_availables, self.clients, self.log_path, ip)

            print(f"[{colored('*', 'cyan')}]Fetching system information, please wait... ")
            self.logIt_thread(self.log_path, msg=f'Calling sysinfo.run()...')
            if sinfo.run(ip):
                print(f"[{colored('V', 'green')}]OK!")

        except (WindowsError, socket.error, ConnectionResetError) as e:
            self.logIt_thread(self.log_path, debug=True, msg=f'Connection Error: {e}.')
            # print(f"[{colored('!', 'red')}]Client lost connection.")
            try:
                self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                self.remove_lost_connection(con, ip)
                return

            except RuntimeError:
                return

    def shell(self, con: str, ip: str) -> None:
        self.logIt_thread(self.log_path, msg=f'Running shell({con}, {ip})...')
        errCount = 0
        while True:
            self.logIt_thread(self.log_path, msg=f'Calling self.show_shell_commands({ip})...')
            self.show_shell_commands(ip)

            # Wait for User Input
            self.logIt_thread(self.log_path, msg=f'Waiting for user input...')
            cmd = input(f"COMMAND@{ip}> ")

            # Input Validation
            try:
                self.logIt_thread(self.log_path, msg=f'Performing input validation on user input: {cmd}...')
                val = int(cmd)

            except (TypeError, ValueError):
                self.logIt_thread(self.log_path, msg=f'Wrong input detected.')
                print(f"[{colored('*', 'red')}]Numbers Only [{colored('1', 'yellow')} - {colored('8', 'yellow')}]!")
                continue

            # Run Custom Command
            if int(cmd) == 100:
                self.logIt_thread(self.log_path, msg=f'Command: 100')
                try:
                    self.logIt_thread(self.log_path, msg=f'Send freestyle command...')
                    con.send("freestyle".encode())
                    self.logIt_thread(self.log_path, msg=f'Send Completed.')

                except (WindowsError, socket.error) as e:
                    self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')
                    break

                for item, connection in zip(self.tmp_availables, self.connections):
                    for conKey, ipValue in self.clients.items():
                        if conKey == connection:
                            for ipKey in ipValue.keys():
                                if item[1] == ipKey:
                                    ipval = item[1]
                                    host = item[2]
                                    user = item[3]

                self.logIt_thread(self.log_path, msg=f'Initializing Freestyle Module...')
                free = freestyle.Freestyle(con, path, self.tmp_availables, self.clients,
                                           log_path, host, user)

                self.logIt_thread(self.log_path, msg=f'Calling freestyle module...')
                free.freestyle(ip)

                continue

            # Tasks
            elif int(cmd) == 5:
                self.logIt_thread(self.log_path, debug=False, msg=f'Running tasks condition...')
                errCount = 0
                if len(self.targets) == 0:
                    self.logIt_thread(self.log_path, debug=False, msg=f'No available connections.')
                    print(f"[{colored('*', 'red')}]No connected stations.")
                    break

                self.logIt_thread(self.log_path, debug=False, msg=f'Initializing Module: tasks...')
                tsks = tasks.Tasks(con, ip, ttl, self.clients, self.connections,
                                   self.targets, self.ips, self.tmp_availables, path, self.log_path)

                self.logIt_thread(self.log_path, debug=False, msg=f'Calling tasks.tasks()...')
                if not tsks.tasks(ip):
                    return False

                self.logIt_thread(self.log_path, debug=False, msg=f'Calling tasks.kill_tasks()...')
                task = tsks.kill_tasks(ip)
                if task is None:
                    continue

                try:
                    self.logIt_thread(self.log_path, debug=False, msg=f'Calling tasks.task_to_kill()...')
                    tasks.task_to_kill(ip)
                    return True

                except (WindowsError, socket.error, ConnectionResetError, ConnectionError) as e:
                    self.logIt_thread(self.log_path, debug=False, msg=f'Connection Error: {e}')
                    print(f"[{colored('!', 'red')}]Client lost connection.")
                    try:
                        self.logIt_thread(self.log_path, debug=False,
                                          msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                        self.remove_lost_connection(con, ip)

                    except RuntimeError as e:
                        self.logIt_thread(self.log_path, debug=False, msg=f'Runtime Error: {e}.')
                        return False

            # Clear Screen
            elif int(cmd) == 7:
                self.logIt_thread(self.log_path, debug=False, msg=f'Running clear screen condition...')
                self.logIt_thread(self.log_path, debug=False, msg=f'Clearing screen...')
                os.system('cls')
                self.logIt_thread(self.log_path, debug=False, msg=f'Screen cleared.')
                continue

            # Back
            elif int(cmd) == 8:
                self.logIt_thread(self.log_path, debug=False, msg=f'Running back condition...')
                self.logIt_thread(self.log_path, debug=False, msg=f'Breaking shell loop...')
                break

        self.logIt_thread(self.log_path, debug=False, msg=f'=== End of shell() ===')

    def remove_lost_connection(self, con: str, ip: str) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running remove_lost_connection({con}, {ip})...')
        try:
            self.logIt_thread(self.log_path, msg=f'Removing connections...')
            for conKey, macValue in self.clients.items():
                if conKey == con:
                    for macKey, ipVal in macValue.items():
                        for ipKey, identValue in ipVal.items():
                            if ipKey == ip:
                                for identKey, userValue in identValue.items():
                                    self.targets.remove(con)
                                    self.ips.remove(ip)

                                    del self.connections[con]
                                    del self.clients[con]

                                    print(f"[{colored('*', 'red')}]{colored(f'{ip}', 'yellow')} | "
                                          f"{colored(f'{identKey}', 'yellow')} | "
                                          f"{colored(f'{userValue}', 'yellow')} "
                                          f"Removed from Availables list.\n")

            self.logIt_thread(self.log_path, msg=f'Connections removed.')
            return True

        except RuntimeError as e:
            self.logIt_thread(self.log_path, msg=f'Runtime Error: {e}.')
            return False

    def selectItem(self, event):
        def make_buttons():
            # Screenshot Button
            self.screenshot_btn = Button(self.controller_btns, text="Screenshot", width=15, pady=5,
                                         command=lambda: self.screenshot(clientConn, ip))

            self.screenshot_btn.grid(row=0, sticky="w", pady=5, padx=2, ipadx=2)

            # System Information Button
            self.sysinfo_btn = Button(self.controller_btns, text="SysInfo", width=15, pady=5,
                                      command=lambda: self.sysinfo(clientConn, ip))

            self.sysinfo_btn.grid(row=0, column=1, sticky="w", pady=5, padx=2, ipadx=2)

            # Last Restart Button
            self.last_restart_btn = Button(self.controller_btns, text="Last Restart", width=15, pady=5,
                                           command=lambda: self.last_restart(clientConn, ip, sname))

            self.last_restart_btn.grid(row=0, column=2, sticky="w", pady=5, padx=2, ipadx=2)

            # Anydesk Button
            self.anydesk_btn = Button(self.controller_btns, text="Anydesk", width=15, pady=5,
                                      command=lambda: self.anydesk(clientConn, ip))

            self.anydesk_btn.grid(row=0, column=3, sticky="w", pady=5, padx=2, ipadx=2)

            # Restart Button
            self.anydesk_btn = Button(self.controller_btns, text="Restart", width=15, pady=5,
                                      command=lambda: self.restart(clientConn, ip, sname))

            self.anydesk_btn.grid(row=0, column=4, sticky="w", pady=5, padx=2, ipadx=2)

        rowid = self.table.identify_row(event.y)
        row = self.table.item(rowid)['values']
        try:
            if not row[2] in self.temp.values():
                self.temp[row[0]] = row[2]

        except IndexError:
            pass

        # finally:
        #     print(self.temp)

        # Create a Controller Box with Buttons and connect to TreeView Table
        for id, ip in self.temp.items():
            for clientConn, clientValues in self.clients.items():
                for clientMac, clientIPv in clientValues.items():
                    for clientIP, vals in clientIPv.items():
                        if clientIP == ip:
                            for sname in vals.keys():
                                make_buttons()

                                shellThread = Thread(target=self.shell, args=(clientConn, clientIP), name="Shell Thread")
                                shellThread.daemon = True
                                shellThread.start()

                                # Reset temp dict
                                self.temp.clear()

                                return


def get_date() -> str:
    d = datetime.now().replace(microsecond=0)
    dt = str(d.strftime("%b %d %Y | %I-%M-%S"))

    return dt


def main(ip: str, port: int) -> None:
    def headline() -> None:
        app.logIt_thread(log_path, debug=False, msg=f'Running headline()...')
        app.logIt_thread(log_path, debug=False, msg=f'Displaying banner...')
        print("\n\t\t▄███████▄    ▄████████    ▄████████  ▄████████    ▄█    █▄")
        print("\t\t███    ███   ███    ███   ███    ███ ███    ███   ███    ███")
        print("\t\t███    ███   ███    █▀    ███    ███ ███    █▀    ███    ███")
        print("\t\t███    ███  ▄███▄▄▄       ███    ███ ███         ▄███▄▄▄▄███▄▄")
        print("\t\t▀█████████▀  ▀▀███▀▀▀     ▀███████████ ███        ▀▀███▀▀▀▀███▀")
        print("\t\t███          ███    █▄    ███    ███ ███    █▄    ███    ███")
        print("\t\t███          ███    ███   ███    ███ ███    ███   ███    ███")
        print("\t\t▄████▀        ██████████   ███    █▀  ████████▀    ███    █▀")
        print(f""
              f"\t\t{colored('|| By Gil Shwartz', 'green')} {colored('@2022 ||', 'yellow')}\n")

        app.logIt_thread(log_path, debug=False, msg=f'Displaying options...')
        print(f"\t\t({colored('1', 'yellow')})Remote Control          ---------------> "
              f"Show Remote Commands")
        print(f"\t\t({colored('2', 'yellow')})Connection History      ---------------> "
              f"Show connection history.")
        print(f"\t\t({colored('3', 'yellow')})Show Connected Stations ---------------> "
              f"Display Current connected stations")
        print(f"\t\t({colored('4', 'yellow')})CLS                     ---------------> "
              f"Clear Local Screen")
        print(f"\t\t({colored('5', 'yellow')})Server Info             ---------------> "
              f"Show Server Information")
        print(f"\t\t({colored('6', 'yellow')})Update clients          ---------------> "
              f"Send an update command to connected clients")
        print(f"\n\t\t({colored('7', 'red')})Exit                     ---------------> "
              f"Close connections and exit program.\n")

        app.logIt_thread(log_path, debug=False, msg=f'=== End of headline() ===')

    def validate() -> str:
        app.logIt_thread(log_path, msg=f'Waiting for user input...')
        command = input("CONTROL@> ")
        app.logIt_thread(log_path, msg=f'User input: {command}.')

        try:
            app.logIt_thread(log_path, msg=f'Performing input validation on {command}...')
            int(command)

            return command

        except ValueError:
            app.logIt_thread(log_path, msg=f'Wrong input detected.')
            print(
                f"[{colored('*', 'red')}]Numbers only. Choose between "
                f"[{colored('1', 'yellow')} - {colored('7', 'yellow')}].\n")

    def remote_shell() -> bool:
        app.logIt_thread(log_path, msg=f'Running remote shell commands condition...')
        if len(app.clients) != 0:
            print(f"{colored('=', 'blue')}=>{colored('Remote Shell', 'red')}<={colored('=', 'blue')}")

            # Show Available Connections
            app.logIt_thread(log_path, msg=f'Calling server.show_available_connections()...')
            app.show_available_connections()

            # Get Number from User and start Remote Shell
            app.logIt_thread(log_path, msg=f'Calling server.get_station_number()...')
            station = app.get_station_number()
            if station:
                app.logIt_thread(log_path, msg=f'Calling server.shell({station[1]}, {station[2]})...')
                if app.shell(station[1], station[2]):
                    return True

        else:
            app.logIt_thread(log_path, msg=f'No available connections.')
            print(f"[{colored('*', 'cyan')}]No available connections.")
            return False

    def choices() -> None:
        app.logIt_thread(log_path, msg=f'Validating input number is in the menu...')
        if int(command) <= 0 or int(command) > 7:
            print(f"[{colored('*', 'red')}]Wrong Number. [{colored('1', 'yellow')} - {colored('7', 'yellow')}]!")
            return False

        # Connection History
        elif int(command) == 2:
            app.logIt_thread(log_path, msg=f'Check if connection history list is empty...')
            if len(app.connHistory) == 0:
                app.logIt_thread(log_path, msg=f'List is empty.')
                print(f"[{colored('*', 'cyan')}]List is empty.")
                return False

            app.logIt_thread(log_path, msg=f'Calling server.connection_history()...')
            app.connection_history()
            return

        # Send Update command
        elif int(command) == 6:
            if len(app.ips) == 0 and len(app.targets) == 0:
                app.logIt_thread(log_path, msg=f'No available connections.')
                print(f"[{colored('*', 'cyan')}]No connected stations.")
                return False

            for client, ip in zip(app.targets, app.ips):
                app.logIt_thread(log_path, msg=f'Sending update command to {ip}...')
                client.send('update'.encode())
                app.logIt_thread(log_path, msg=f'Update command sent.')
                app.logIt_thread(log_path, msg=f'Waiting for response from {ip}...')
                msg = client.recv(1024).decode()
                app.logIt_thread(log_path, msg=f'Response from {ip}: {msg}')

        # Exit Program
        elif int(command) == 7:
            app.logIt_thread(log_path, msg=f'User input: 6 | Exiting app...')

            if len(app.targets) > 0:
                try:
                    for t in app.targets:
                        app.logIt_thread(log_path, msg=f'Sending exit command to connected stations...')
                        t.send('exit'.encode())
                        app.logIt_thread(log_path, msg=f'Send completed.')

                        app.logIt_thread(log_path, msg=f'Closing socket connections...')
                        t.close()
                        app.logIt_thread(log_path, msg=f'Socket connections closed.')

                except ConnectionResetError as e:
                    app.logIt_thread(log_path, debug=True, msg=f'Connection Error: {e}.')
                    print(f"[{colored('X', 'red')}]Connection Reset by client.")

                    app.logIt_thread(log_path, debug=True, msg=f'Exiting app with code 1...')
                    sys.exit(1)

            app.logIt_thread(log_path, msg=f'Exiting app with code 0...')
            sys.exit(0)

    while True:
        app.logIt_thread(log_path, msg=f'Running main()...')
        app.logIt_thread(log_path, msg=f'Calling headline()...')
        headline()

        app.logIt_thread(log_path, msg=f'Calling validate()...')
        command = validate()
        app.logIt_thread(log_path, msg=f'Validated command: {command}')

        app.logIt_thread(log_path, msg=f'Calling choices()...')
        choices()


if __name__ == '__main__':
    app = App()
    app.mainloop()

    # COLORS
    # root = tk.Tk()
    # app = ColorChart(root)
    # root.mainloop()
