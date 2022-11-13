import concurrent.futures

from PIL import Image, ImageTk
from datetime import datetime
from termcolor import colored
from threading import Thread
from colorama import init
import subprocess
import threading
import os.path
import socket
import psutil
import time
import sys

# Threadpool Executor
from concurrent.futures import ThreadPoolExecutor

# GUI
from tkinter import simpledialog
from tkinter import messagebox
from tkinter import ttk
from tkinter import *
import tkinter as tk
import tkinter

# Local Modules
from Modules import vital_signs
from Modules import screenshot
from Modules import freestyle
from Modules import sysinfo
from Modules import tasks

init()


class App(tk.Tk):
    clients = {}
    connections = {}
    connHistory = []
    ips = []
    targets = []
    buttons = []

    # Temp dict to hold connected station's ID# & IP
    temp = {}

    port = 55400
    ttl = 5
    hostname = socket.gethostname()
    serverIP = str(socket.gethostbyname(hostname))
    path = r'c:\Peach'
    log_path = fr'{path}\server_log.txt'

    WIDTH = 1350
    HEIGHT = 880

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
        # Set Window Title
        self.title("Peach")
        self.iconbitmap('peach.ico')

        # Update screen geometry variables
        self.update_idletasks()
        self.width = self.winfo_screenwidth()
        self.height = self.winfo_screenheight()

        # Set Mid Screen Coordinates
        x = (self.width / 2) - (self.WIDTH / 2)
        y = (self.height / 2) - (self.HEIGHT / 2)

        # Set Window Size & Location
        self.geometry(f'{self.WIDTH}x{self.HEIGHT}+{int(x)}+{int(y)}')

        # Set Closing protocol
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
        self.main_frame.grid(row=0, column=1, columnspan=5, sticky="nswe", padx=5)
        self.main_frame.rowconfigure(5, weight=1)

        # Main Frame top bar - shows server information
        self.main_frame_top = Frame(self.main_frame, relief='flat', height=30)
        self.main_frame_top.grid(row=0, column=1, sticky="nwes")

        # Main frame top bar LabelFrame
        self.top_bar_label = LabelFrame(self.main_frame, text="Server Information", relief='solid')
        self.top_bar_label.grid(row=0, column=1, sticky='news')

        # Table Frame in Main Frame
        self.main_frame_table = Frame(self.main_frame, relief='flat')
        self.main_frame_table.grid(row=1, column=1, sticky="news", pady=5)

        # Controller Buttons LabelFrame in Main Frame
        self.controller_btns = LabelFrame(self.main_frame, text="Controller", relief='solid', height=60)
        self.controller_btns.grid(row=2, column=0, columnspan=5, sticky="ews", pady=5)

        # Create Connected Table inside Main Frame when show connected btn pressed
        self.table_frame = ttk.LabelFrame(self.main_frame_table, text="Connected Stations")
        self.table_frame.grid(row=0, sticky="new", pady=5)

        # Status LabelFrame
        self.status_labelFrame = LabelFrame(self.main_frame, height=5, text='Status', relief='solid', pady=5)
        self.status_labelFrame.grid(row=5, column=1, sticky='news')

        # =-=-=-=-=-=-= BUTTONS =-=-=-=-=-=-=-=
        # Sidebar Buttons
        # Refresh Button
        self.refresh_bt = tk.Button(self.sidebar_frame,
                                    text="Refresh", width=15, pady=10,
                                    command=lambda: self.refresh())
        self.refresh_bt.grid(row=0, sticky="nwes")

        # Connection History
        self.connection_history_btn = tk.Button(self.sidebar_frame, text="History", width=15, pady=10,
                                                command=lambda: self.connection_history_thread())
        self.connection_history_btn.grid(row=1, sticky='news')

        # Update Clients Button
        self.btn_update_clients = tk.Button(self.sidebar_frame,
                                            text="Update All Clients", width=15, pady=10,
                                            command=lambda: self.update_all_clients())

        self.btn_update_clients.grid(row=2, sticky="nwes")

        # EXIT Button
        self.btn_exit = tk.Button(self.sidebar_frame,
                                  text="Exit", width=15, pady=10,
                                  command=lambda: self.exit())
        self.btn_exit.grid(row=3, sticky="nwes")
        # =-=-=-=-=-=-= END BUTTONS =-=-=-=-=-=-=-=

        # Display Connected Table
        self.create_connected_table()

        # Display Server info & connected stations
        self.server_information()
        self.show_available_connections()
        self.connection_history()

        # Display Status Message
        self.status_message = Label(self.status_labelFrame, relief='flat', text=f"Status: Welcome to Peach!\t\t\t\t")
        self.status_message.grid(row=0, sticky='w')

    def create_connected_table(self) -> None:
        # Create a Table for connected stations
        self.connected_table = ttk.Treeview(self.table_frame,
                                            columns=("ID", "MAC Address",
                                                     "IP Address", "Station Name",
                                                     "Logged User", "Client Version"),
                                            show="headings", height=10, selectmode='browse')
        self.connected_table.grid(row=0, column=1, pady=10)

        # Create Scrollbar
        self.table_sb = Scrollbar(self.table_frame, orient=VERTICAL)
        self.table_sb.grid(row=0, sticky="wns")

        # Columns & Headings config
        self.connected_table.column("#1", anchor=CENTER)
        self.connected_table.heading("#1", text="ID")
        self.connected_table.column("#2", anchor=CENTER)
        self.connected_table.heading("#2", text="MAC")
        self.connected_table.column("#3", anchor=CENTER)
        self.connected_table.heading("#3", text="IP")
        self.connected_table.column("#4", anchor=CENTER)
        self.connected_table.heading("#4", text="Station Name")
        self.connected_table.column("#5", anchor=CENTER)
        self.connected_table.heading("#5", text="Logged User")
        self.connected_table.column("#6", anchor=CENTER)
        self.connected_table.heading("#6", text="Client Version")
        self.connected_table.bind("<Button 1>", self.selectItem)

        # Style Table
        self.connected_table_style = ttk.Style()
        self.connected_table_style.configure("Treeview", rowheight=20)
        self.connected_table_style.map("Treeview")

    def update_all_clients(self) -> bool:
        for client, ip in zip(self.targets, self.ips):
            self.logIt_thread(self.log_path, msg=f'Sending update command to {ip}...')
            try:
                client.send('update'.encode())

            except socket.error:
                return False

            self.logIt_thread(self.log_path, msg=f'Update command sent.')
            self.logIt_thread(self.log_path, msg=f'Waiting for response from {ip}...')
            try:
                msg = client.recv(1024).decode()

            except socket.error:
                return False

            self.logIt_thread(self.log_path, msg=f'Response from {ip}: {msg}')

            # Display Progress status in Status LabelFrame
            runningLabel = Label(self.status_labelFrame, relief='flat', text=f"From {ip}: {msg}\t\t\t\t")
            runningLabel.grid(row=0, column=0, sticky='news')

            messagebox.showinfo(f"From {ip}", f"{msg}\t\t\t")
            self.remove_lost_connection(client, ip)

        self.refresh()
        return True

    # Refresh server info & connected stations table with vital signs
    def refresh(self) -> None:
        self.tmp_availables = []
        self.vital_signs_thread()
        self.server_information()
        self.show_available_connections()

        # Display Status Message
        self.status_message = Label(self.status_labelFrame, relief='flat', text=f"Status: refresh complete.\t\t\t\t")
        self.status_message.grid(row=0, sticky='w')

    # Connection History Thread
    def connection_history_thread(self) -> None:
        connhistThread = Thread(target=self.connection_history, name="Connection History Thread")
        connhistThread.start()

    # Vitals Thread
    def vital_signs_thread(self) -> None:
        vitalsThread = Thread(target=self.vital_signs, name="Vitals Thread")
        vitalsThread.start()

    # Display Server Information Thread
    def display_server_information_thread(self) -> None:
        # Display Server Information
        infoThread = Thread(target=self.server_information, name="ServerInfo")
        # infoThread.daemon = True
        infoThread.start()

    # Display Server Information
    def server_information(self) -> dict:
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
    def sac_thread(self) -> None:
        self.sacThread = Thread(target=self.show_available_connections,
                                name="Show Available Connections Thread")
        # self.sacThread.daemon = True
        self.sacThread.start()

    # Show Available Connections
    def show_available_connections(self) -> None:
        if len(self.ips) == 0 and len(self.targets) == 0:
            self.logIt_thread(self.log_path, msg=f'No connected Stations')
            # print(f"[{colored('*', 'cyan')}]No connected stations.\n")

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
                                self.connected_table.insert('', 'end', values=(session, stationMAC, stationIP,
                                                                               stationName, loggedUser, clientVersion))

            self.logIt_thread(self.log_path, msg=f'Extraction completed.')

        # Cleaning availables list
        self.logIt_thread(self.log_path, msg=f'Cleaning availables list...')
        self.tmp_availables = []

        # Clear previous entries in GUI table
        self.connected_table.delete(*self.connected_table.get_children())

        self.logIt_thread(self.log_path, msg=f'Creating available list...')
        make_tmp()

        self.logIt_thread(self.log_path,
                          msg=f'Extracting: Session | Station IP | Station Name | Logged User '
                              f'from clients list...')
        extract()

    # Close App
    def on_closing(self, event=0) -> None:
        self.destroy()

    # EXIT
    def exit(self) -> None:
        if len(self.targets) > 0:
            try:
                for t in self.targets:
                    self.logIt_thread(self.log_path, msg=f'Sending exit command to connected stations...')
                    t.send('exit'.encode())
                    self.logIt_thread(self.log_path, msg=f'Send completed.')

                    self.logIt_thread(self.log_path, msg=f'Closing socket connections...')
                    t.close()
                    self.logIt_thread(self.log_path, msg=f'Socket connections closed.')

            except ConnectionResetError as e:
                self.logIt_thread(self.log_path, debug=True, msg=f'Connection Error: {e}.')
                # print(f"[{colored('X', 'red')}]Connection Reset by client.")

                self.logIt_thread(self.log_path, debug=True, msg=f'Exiting app with code 1...')
                sys.exit(1)

        self.logIt_thread(self.log_path, msg=f'Exiting app with code 0...')
        self.destroy()
        sys.exit(0)

    # ================ Utilities ================
    def bytes_to_number(self, b: int) -> int:
        self.logIt_thread(self.log_path, msg=f'Running bytes_to_number({b})...')
        dt = self.get_date()
        res = 0
        for i in range(4):
            res += b[i] << (i * 8)
        return res

    # Get current date & time
    def get_date(self) -> str:
        d = datetime.now().replace(microsecond=0)
        dt = str(d.strftime("%m/%d/%Y %H:%M:%S"))

        return dt

    # Log Debugger
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

    # Run log func in new Thread
    def logIt_thread(self, log_path=None, debug=False, msg='') -> None:
        self.logit_thread = Thread(target=self.logIt, args=(log_path, debug, msg), name="Log Thread")
        self.logit_thread.daemon = True
        self.logit_thread.start()

    # Run Connect func in a new Thread
    def run(self) -> None:
        self.logIt_thread(self.log_path, msg=f'Running run()...')
        self.logIt_thread(self.log_path, msg=f'Calling connect() in new thread...')
        self.connectThread = Thread(target=self.connect, name=f"Connect Thread")
        self.connectThread.start()

        self.logIt_thread(self.log_path, msg=f'Adding thread to threads list...')
        self.logIt_thread(self.log_path, msg=f'Thread added to threads list.')

    # Listen for connections and sort new connections to designated lists/dicts
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
                self.hostname = get_hostname()

                # Get Current User
                self.loggedUser = get_user()

                # Get Client Version
                self.client_version = get_client_version()

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
            dt = self.get_date()
            self.logIt_thread(self.log_path, msg=f'Creating a connection dict...')
            self.temp_connection_record = {self.conn: {self.client_mac: {self.ip: {self.ident: {self.user: dt}}}}}
            self.logIt_thread(self.log_path, msg=f'Connection dict created: {self.temp_connection_record}')

            # Add Connection to Connection History
            self.logIt_thread(self.log_path, msg=f'Adding connection to connection history...')
            self.connHistory.append(self.temp_connection_record)
            self.logIt_thread(self.log_path, msg=f'Connection added to connection history.')

            self.logIt_thread(self.log_path, msg=f'Calling self.welcome_message() condition...')
            self.welcome_message()

    # Send welcome message to connected clients
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

    # Display Connection History
    def connection_history(self) -> None:
        self.logIt_thread(self.log_path, msg=f'Running connection_history()...')

        # History LabelFrame
        self.history_labelFrame = LabelFrame(self.main_frame, height=400, text="Connection History",
                                             relief='ridge')
        self.history_labelFrame.grid(row=3, sticky='news', columnspan=3)

        c = 1  # Initiate Counter for Connection Number
        try:
            # Iterate Through Connection History List Items
            self.logIt_thread(self.log_path, msg=f'Iterating self.connHistory...')
            for connection in self.connHistory:
                for conKey, macValue in connection.items():
                    for macKey, ipVal in macValue.items():
                        for ipKey, identValue in ipVal.items():
                            for identKey, userValue in identValue.items():
                                for userKey, timeValue in userValue.items():
                                    print(
                                        f"[{colored(str(c), 'green')}]{colored('IP', 'cyan')}: {ipKey} | "
                                        f"{colored('Station MAC', 'cyan')}: {macKey} | "
                                        f"{colored('Station Name', 'cyan')}: {identKey} | "
                                        f"{colored('User', 'cyan')}: {userKey} | "
                                        f"{colored('Time', 'cyan')}: {str(timeValue).replace('|', ':')}")

                                    histLabel = tk.Label(self.history_labelFrame,
                                                         text=f"[{str(c)}]IP: {ipKey} | "
                                                              f"Station MAC: {macKey} | "
                                                              f"Station Name: {identKey} | "
                                                              f"User: {userKey} | "
                                                              f"Time: {str(timeValue).replace('|', ':')}")
                                    histLabel.grid(row=c - 1, column=0, sticky='w')
                        c += 1

        # Break If Client Lost Connection
        except (KeyError, socket.error, ConnectionResetError) as e:
            self.logIt_thread(self.log_path, msg=f'Iteration Error: {e}')
            return

    # Check if connected stations are still connected
    def vital_signs(self) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running vital_signs()...')
        if len(self.targets) == 0:
            messagebox.showinfo("Refresh", "No Connected Stations.")
            return False

        callback = 'yes'
        i = 0

        # Display Progress status in Status LabelFrame
        runningLabel = Label(self.status_labelFrame, relief='flat', text="Status: running vitals check...\t\t\t\t\t\t\t\t")
        runningLabel.grid(row=0, column=0, sticky='w')

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
                                    self.remove_lost_connection(conKey, ipKey)

        self.logIt_thread(self.log_path, msg=f'=== End of vital_signs() ===')
        print(f"\n[{colored('*', 'green')}]Vital Signs Process completed.\n")

        # Display Status message
        runningLabel = Label(self.status_labelFrame, text="Status: Vitals check completed.\t\t\t\t\t\t\t\t")
        runningLabel.grid(row=0, sticky='w')

        return True

    # Restart Client
    def restart(self, con: str, ip: str, sname: str) -> bool:
        # Display MessageBox on screen
        self.sure = messagebox.askyesno(f"Restart for: {ip} | {sname}", f"Are you sure you want to restart {sname}?\t")
        if self.sure:
            try:
                self.logIt_thread(self.log_path, msg=f'Sending restart command to client...')
                con.send('restart'.encode())
                self.remove_lost_connection(con, ip)
                self.refresh()
                return True

            except (RuntimeError, WindowsError, socket.error) as e:
                self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')
                print(f"[{colored('!', 'red')}]Client lost connection.")

                self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                self.remove_lost_connection(con, ip)
                return False

        else:
            return False

    # Display Clients Last Restart
    def last_restart(self, con: str, ip: str, sname: str) -> bool:
        try:
            self.logIt_thread(self.log_path, debug=False, msg=f'Sending lr command to client...')
            con.send('lr'.encode())
            self.logIt_thread(self.log_path, debug=False, msg=f'Send Completed.')

            self.logIt_thread(self.log_path, debug=False, msg=f'Waiting for response from client...')
            msg = con.recv(4096).decode()
            self.logIt_thread(self.log_path, debug=False, msg=f'Client response: {msg}')

            # Display Status Message
            runningLabel = Label(self.status_labelFrame, relief='flat',
                                 text=f"Status: last restart: {msg}\t\t\t\t\t\t\t\t")
            runningLabel.grid(row=0, column=0, sticky='w')

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

    # Run Anydesk on Client
    def anydesk(self, con: str, ip: str, sname: str) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running anydesk({con}, {ip})...')

        # Display Status Message
        runningLabel = Label(self.status_labelFrame, relief='flat', text=f"Status: running anydesk on {ip} | {sname}...\t\t\t\t\t\t\t\t")
        runningLabel.grid(row=0, column=0, sticky='w')

        try:
            self.logIt_thread(self.log_path, msg=f'Sending anydesk command to {con}...')
            con.send('anydesk'.encode())
            self.logIt_thread(self.log_path, msg=f'Send Completed.')

            self.logIt_thread(self.log_path, msg=f'Waiting for response from client...')
            msg = con.recv(1024).decode()
            self.logIt_thread(self.log_path, msg=f'Client response: {msg}.')

            if "OK" not in msg:
                self.logIt_thread(self.log_path, msg=f'Printing msg from client...')
                install_anydesk = messagebox.askyesno("Install Anydesk",
                                                      "Anydesk isn't installed on the remote machine. do you with to install?")

                if install_anydesk:
                    # Display Status Message
                    runningLabel = Label(self.status_labelFrame, relief='flat',
                                         text=f"Status: Installing Anydesk on {sname}...\t\t\t\t\t\t\t\t")
                    runningLabel.grid(row=0, column=0, sticky='w')

                    self.logIt_thread(self.log_path, msg=f'Sending install command to {con}...')
                    con.send('y'.encode())
                    self.logIt_thread(self.log_path, msg=f'Send Completed.')

                    textVar = StringVar()
                    while True:
                        self.logIt_thread(self.log_path, msg=f'Waiting for response from client...')
                        msg = con.recv(1024).decode()
                        self.logIt_thread(self.log_path, msg=f'Client response: {msg}.')
                        textVar.set(msg)

                        if "OK" not in str(msg):
                            # Display Status Message
                            runningLabel = Label(self.status_labelFrame, relief='flat',
                                                 text=f"Status: {msg}...\t\t\t\t\t\t\t\t")
                            runningLabel.grid(row=0, column=0, sticky='w')
                            # print(msg)

                        else:
                            # Display Status Message
                            runningLabel = Label(self.status_labelFrame, relief='flat',
                                                 textvariable=f"{textVar}\t\t\t\t\t\t\t\t")
                            runningLabel.grid(row=0, column=0, sticky='w')

                            time.sleep(0.5)
                            msgBox = messagebox.showinfo(f"From {ip} | {sname}", f"Anydesk Running.\t\t\t\t")

                            # Display Status Message
                            runningLabel = Label(self.status_labelFrame, relief='flat',
                                                 text=f"Status: anydesk running on {ip} | {sname}.\t\t\t\t\t\t\t\t")
                            runningLabel.grid(row=0, column=0, sticky='w')

                            return

                else:
                    self.logIt_thread(self.log_path, msg=f'Sending cancel command to {con}...')
                    con.send('n'.encode())
                    self.logIt_thread(self.log_path, msg=f'Send Completed.')
                    return

            else:
                # Display Status Message
                runningLabel = Label(self.status_labelFrame, relief='flat',
                                     text=f"Status: anydesk running on {ip} | {sname}.\t\t\t\t\t\t\t\t")
                runningLabel.grid(row=0, column=0, sticky='w')

                time.sleep(0.5)
                msgBox = messagebox.showinfo(f"From {ip} | {sname}", f"Anydesk Running.\t\t\t\t")

                return True

        except (WindowsError, ConnectionError, socket.error) as e:
            self.logIt_thread(self.log_path, msg=f'Connection Error: {e}.')

            # Display Status Message
            runningLabel = Label(self.status_labelFrame, relief='flat',
                                 text=f"{ip} | {sname} ERROR: {e}.\t\t\t\t")
            runningLabel.grid(row=0, column=0, sticky='w')

            print(f"[{colored('!', 'red')}]Client lost connection.")
            try:
                self.logIt_thread(self.log_path, debug=True,
                                  msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                self.remove_lost_connection(con, ip)
                return False

            except RuntimeError as e:
                self.logIt_thread(self.log_path, debug=True, msg=f'Runtime Error: {e}.')
                return False

    # Screenshot from Client
    def screenshot(self, con: str, ip: str, sname: str) -> None:
        # Disable Controller Buttons
        disThread = Thread(target=self.disable_controller_buttons, name="Disable Controller Buttons Thread")
        disThread.start()

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

            # Display Status Message
            runningLabel = Label(self.status_labelFrame, relief='flat',
                                 text=f"Status: screenshot from {ip} | {sname} received.\t\t\t\t\t\t\t\t")
            runningLabel.grid(row=0, column=0, sticky='w')

            # Terminate disThread
            disThread.join(1)

        except (WindowsError, socket.error, ConnectionResetError) as e:
            self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')
            print(f"[{colored('!', 'red')}]Client lost connection.")

            self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip}...)')
            self.remove_lost_connection(con, ip)

    # Client System Information
    def sysinfo(self, con: str, ip: str, sname: str):
        # Disable Buttons
        disThread = Thread(target=self.disable_controller_buttons, name="Disable Controller Buttons Thread")
        disThread.start()

        # Display Status Message
        runningLabel = Label(self.status_labelFrame, relief='flat',
                             text=f"Status: waiting for system information from {ip} | {sname}...\t\t\t\t\t\t\t\t")
        runningLabel.grid(row=0, column=0, sticky='w')

        try:
            self.logIt_thread(self.log_path, msg=f'Initializing Module: sysinfo...')
            sinfo = sysinfo.Sysinfo(con, self.ttl, self.path, self.tmp_availables, self.clients, self.log_path, ip)

            print(f"[{colored('*', 'cyan')}]Fetching system information, please wait... ")
            self.logIt_thread(self.log_path, msg=f'Calling sysinfo.run()...')
            if sinfo.run(ip):
                messagebox.showinfo(f"From {ip} | {sname}", "System information file received.\t\t\t\t\t\t\t\t")

                # Display Status Message
                runningLabel = Label(self.status_labelFrame, relief='flat',
                                     text=f"Status: sysinfo file received from {ip} | {sname}.\t\t\t\t\t\t\t\t")
                runningLabel.grid(row=0, column=0, sticky='w')

            # Terminate disThread
            disThread.join(1)

        except (WindowsError, socket.error, ConnectionResetError) as e:
            self.logIt_thread(self.log_path, debug=True, msg=f'Connection Error: {e}.')
            # print(f"[{colored('!', 'red')}]Client lost connection.")
            try:
                self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                self.remove_lost_connection(con, ip)
                return

            except RuntimeError:
                return

    # Display/Kill Tasks on Client
    def tasks(self, con: str, ip: str, sname: str) -> bool:
        if len(self.targets) == 0:
            self.logIt_thread(self.log_path, debug=False, msg=f'No available connections.')
            print(f"[{colored('*', 'red')}]No connected stations.")
            return False

        # Disable Buttons
        disThread = Thread(target=self.disable_controller_buttons, name="Disable Controller Buttons Thread")
        disThread.start()

        # Display Status Message
        runningLabel = Label(self.status_labelFrame, relief='flat',
                             text=f"Status: running tasks on {ip} | {sname}...\t\t\t\t\t\t\t\t")
        runningLabel.grid(row=0, column=0, sticky='w')

        self.logIt_thread(self.log_path, debug=False, msg=f'Initializing Module: tasks...')
        tsks = tasks.Tasks(con, ip, self.clients, self.connections,
                           self.targets, self.ips, self.tmp_availables,
                           self.path, self.log_path, self.path, sname)

        self.logIt_thread(self.log_path, debug=False, msg=f'Calling tasks.tasks()...')
        filepath = tsks.tasks(ip)

        killTask = messagebox.askyesno(f"Tasks from {ip} | {sname}", "Kill Task?\t\t\t\t\t\t\t\t")
        if killTask:
            try:
                task_to_kill = simpledialog.askstring(parent=self, title='Task To Kill', prompt="Task to kill\t\t\t\t")
                if task_to_kill is None:
                    con.send('n'.encode())
                    return False

                if len(task_to_kill) < 1:
                    con.send('n'.encode())
                    return False

                if not str(task_to_kill).endswith('exe'):
                    return False

                confirmKill = messagebox.askyesno(f'Kill task: {task_to_kill} on {sname}',
                                                  f'Are you sure you want to kill {task_to_kill}?')

                if confirmKill:
                    try:
                        self.logIt_thread(self.log_path, msg=f'Sending kill command to {ip}.')
                        con.send('kill'.encode())
                        self.logIt_thread(self.log_path, msg=f'Send complete.')

                        self.logIt_thread(self.log_path, msg=f'Sending task name to {ip}...')
                        con.send(task_to_kill.encode())
                        self.logIt_thread(self.log_path, msg=f'Send complete.')

                        self.logIt_thread(self.log_path, msg=f'Waiting for confirmation from {ip}...')
                        msg = con.recv(1024).decode()
                        self.logIt_thread(self.log_path, msg=f'{ip}: {msg}')
                        print(f"[{colored('*', 'green')}]{msg}\n")

                        messagebox.showinfo(f'Kill {task_to_kill}', f'Task {task_to_kill} killed.')

                        # Display Status Message
                        runningLabel = Label(self.status_labelFrame, relief='flat',
                                             text=f"Status: killed {task_to_kill} on {ip} | {sname}...\t\t\t\t\t\t\t\t")
                        runningLabel.grid(row=0, column=0, sticky='w')

                        return True

                    except (WindowsError, socket.error) as e:
                        self.logIt_thread(self.log_path, msg=f'Error: {e}.')
                        print(f"[{colored('!', 'red')}]Client lost connection.")
                        self.remove_lost_connection(con, ip)
                        return False

                else:
                    self.logIt_thread(self.log_path, msg=f'Sending pass command to {ip}.')
                    con.send('pass'.encode())
                    self.logIt_thread(self.log_path, msg=f'Send complete.')

                    # Terminate disThread
                    disThread.join(1)

                    return False

            except (WindowsError, socket.error, ConnectionResetError, ConnectionError) as e:
                print(f"[{colored('!', 'red')}]Client lost connection.")
                try:
                    self.remove_lost_connection(con, ip)

                except RuntimeError as e:
                    return False

        else:
            con.send('n'.encode())

            # Display Status Message
            runningLabel = Label(self.status_labelFrame, relief='flat',
                                 text=f"Status: received tasks from {ip} | {sname}.\t\t\t\t\t\t\t\t")
            runningLabel.grid(row=0, column=0, sticky='news')

            return True

    # Browse local files by Clients Station Names
    def browse_local_files(self, sname: str) -> subprocess:
        return subprocess.Popen(rf"explorer {self.path}\{sname}")

    # Shell Connection to Client
    def shell(self, con: str, ip: str, sname: str) -> None:
        self.logIt_thread(self.log_path, msg=f'Running shell({con}, {ip})...')

        # Display Status message
        runningLabel = Label(self.status_labelFrame, relief='flat', text=f"Status: shell connected to: {ip} | {sname}\t\t\t\t\t\t\t\t")
        runningLabel.grid(row=0, column=0, sticky='w')

        while True:
            self.logIt_thread(self.log_path, msg=f'Calling self.show_shell_commands({ip})...')
            # self.show_shell_commands(ip)

            # Wait for User Input
            self.logIt_thread(self.log_path, msg=f'Waiting for user input...')
            cmd = input(f"")

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

    # Remove Lost connections
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

                                    # Display Status Message
                                    runningLabel = Label(self.status_labelFrame, relief='flat',
                                                         text=f"Status: {ip} | {identValue} | {userValue} removed from connected list.\t\t\t\t\t\t\t\t")
                                    runningLabel.grid(row=0, column=0, sticky='w')

            self.logIt_thread(self.log_path, msg=f'Connections removed.')

            return True

        except RuntimeError as e:
            self.logIt_thread(self.log_path, msg=f'Runtime Error: {e}.')
            return False

    # Disable Controller Buttons
    def disable_controller_buttons(self):
        for button in list(self.buttons):
            button.config(state=DISABLED)

        time.sleep(3)

        for button in list(self.buttons):
            button.config(state=NORMAL)

    # Manage Table & Controller LabelFrame Buttons
    def selectItem(self, event) -> bool:
        # Create Controller Buttons
        def make_buttons():
            # Screenshot Button
            self.screenshot_btn = Button(self.controller_btns, text="Screenshot", width=15, pady=5,
                                         command=lambda: self.screenshot(clientConn, clientIP, sname))
            self.screenshot_btn.grid(row=0, sticky="w", pady=5, padx=2, ipadx=2)
            self.buttons.append(self.screenshot_btn)

            # Anydesk Button
            self.anydesk_btn = Button(self.controller_btns, text="Anydesk", width=15, pady=5,
                                      command=lambda: self.anydesk(clientConn, ip, sname))

            self.anydesk_btn.grid(row=0, column=1, sticky="w", pady=5, padx=2, ipadx=2)
            self.buttons.append(self.anydesk_btn)

            # Last Restart Button
            self.last_restart_btn = Button(self.controller_btns, text="Last Restart", width=15, pady=5,
                                           command=lambda: self.last_restart(clientConn, ip, sname))

            self.last_restart_btn.grid(row=0, column=2, sticky="w", pady=5, padx=2, ipadx=2)
            self.buttons.append(self.last_restart_btn)

            # System Information Button
            self.sysinfo_btn = Button(self.controller_btns, text="SysInfo", width=15, pady=5,
                                      command=lambda: self.sysinfo(clientConn, clientIP, sname))

            self.sysinfo_btn.grid(row=0, column=3, sticky="w", pady=5, padx=2, ipadx=2)
            self.buttons.append(self.sysinfo_btn)

            # Tasks Button
            self.tasks_btn = Button(self.controller_btns, text="Tasks", width=15, pady=5,
                                    command=lambda: self.tasks(clientConn, clientIP, sname))

            self.tasks_btn.grid(row=0, column=4, sticky="w", pady=5, padx=2, ipadx=2)
            self.buttons.append(self.tasks_btn)

            # Restart Button
            self.restart_btn = Button(self.controller_btns, text="Restart", width=15, pady=5,
                                      command=lambda: self.restart(clientConn, ip, sname))

            self.restart_btn.grid(row=0, column=5, sticky="w", pady=5, padx=2, ipadx=2)
            self.buttons.append(self.restart_btn)

            # Browse Local Files Button
            self.browse_btn = Button(self.controller_btns, text="Local Files", width=15, pady=5,
                                     command=lambda: self.browse_local_files(sname))

            self.browse_btn.grid(row=0, column=6, sticky="w", pady=5, padx=2, ipadx=2)
            self.buttons.append(self.browse_btn)

        # Respond to mouse clicks on connected table
        rowid = self.connected_table.identify_row(event.y)
        row = self.connected_table.item(rowid)['values']
        try:
            if not row[2] in self.temp.values():
                self.temp[row[0]] = row[2]

        # Error can raise when clicking on empty space so the row is None or empty.
        except IndexError:
            pass

        # Details LabelFrame
        self.details_labelFrame = LabelFrame(self.main_frame, text="Details", relief='ridge', height=400)
        self.details_labelFrame.grid(row=3, sticky='news', columnspan=3)

        # Create a Controller Box with Buttons and connect shell by TreeView Table selection
        for id, ip in self.temp.items():
            for clientConn, clientValues in self.clients.items():
                for clientMac, clientIPv in clientValues.items():
                    for clientIP, vals in clientIPv.items():
                        if clientIP == ip:
                            for sname in vals.keys():
                                make_buttons()

                                shellThread = Thread(target=self.shell, args=(clientConn, clientIP, sname),
                                                     name="Shell Thread")
                                shellThread.daemon = True
                                shellThread.start()

                                # Reset temp dict
                                self.temp.clear()

                                return True


if __name__ == '__main__':
    app = App()
    app.mainloop()
