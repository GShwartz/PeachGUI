import glob
import tkinter

import PIL.Image
from PIL import Image, ImageTk
from datetime import datetime
from threading import Thread
import subprocess
import threading
import os.path
import socket
import psutil
import time
import sys

# GUI
from tkinter import simpledialog
from tkinter import messagebox
from tkinter import ttk
from tkinter import *
import tkinter as tk

# import tkinter

# Local Modules
from Modules import vital_signs
from Modules import screenshot
from Modules import freestyle
from Modules import sysinfo
from Modules import tasks


# TODO: Create tools Class
# TODO: Add Menubar


class App(tk.Tk):
    clients = {}
    connections = {}
    connHistory = []
    ips = []
    targets = []
    buttons = []
    sidebar_buttons = []
    notebook_tabs = []
    counter = 0

    # Temp dict to hold connected station's ID# & IP
    temp = {}

    port = 55400
    ttl = 5
    hostname = socket.gethostname()
    serverIP = str(socket.gethostbyname(hostname))
    path = r'c:\Peach'
    log_path = fr'{path}\server_log.txt'

    WIDTH = 1350
    HEIGHT = 830

    def __init__(self):
        super().__init__()
        self.style = ttk.Style()

        # ======== Server Config ==========
        # Listener
        self.listener()

        # Create local app DIR
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        # Run Listener Thread
        listenerThread = Thread(target=self.run, name="Listener Thread")
        listenerThread.daemon = True
        listenerThread.start()

        # ======== GUI Config ===========
        # Set main window preferences

        self.title("Peach")
        self.iconbitmap('peach.ico')

        # Update screen geometry variables
        self.update_idletasks()

        # Get current screen width & height
        self.width = self.winfo_screenwidth()
        self.height = self.winfo_screenheight()

        # Set Mid Screen Coordinates
        x = (self.width / 2) - (self.WIDTH / 2)
        y = (self.height / 2) - (self.HEIGHT / 2)

        # Set Window Size & Location & Center Window
        self.geometry(f'{self.WIDTH}x{self.HEIGHT}+{int(x)}+{int(y)}')
        self.maxsize(f'{self.WIDTH}', f'{self.HEIGHT}')
        self.minsize(f'{self.WIDTH}', f'{self.HEIGHT}')

        # Set Closing protocol
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Main Window Frames
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # =-=-=-=-=-=-= MAIN FRAME GUI =-=-=-=-=-=-=-=
        self.make_style()

        # Build and display
        self.build_main_window_frames()
        self.build_connected_table()
        self.build_sidebar_buttons()

        # Display Server info & connected stations
        self.server_information()
        self.show_available_connections()
        self.connection_history()

    # ==++==++==++== THREADED FUNCS ==++==++==++== #
    # Run log func in new Thread
    def logIt_thread(self, log_path=None, debug=False, msg='') -> None:
        self.logit_thread = Thread(target=self.logIt, args=(log_path, debug, msg), name="Log Thread")
        self.logit_thread.daemon = True
        self.logit_thread.start()

    # Update status bar messages Thread
    def update_statusbar_messages_thread(self, msg=''):
        statusbarThread = Thread(target=self.update_statusbar_messages,
                                 args=(msg,),
                                 name="Update Statusbar Thread")
        statusbarThread.daemon = True
        statusbarThread.start()

    # Display Server Information Thread
    def display_server_information_thread(self) -> None:
        # Display Server Information
        infoThread = Thread(target=self.server_information, name="ServerInfo")
        # infoThread.daemon = True
        infoThread.start()

    # Vitals Thread
    def vital_signs_thread(self) -> None:
        vitalsThread = Thread(target=self.vital_signs, name="Vitals Thread")
        vitalsThread.start()

    # Update Client Thread
    def update_all_clients_thread(self):
        update = Thread(target=self.update_all_clients,
                        daemon=True,
                        name="Update All Clients Thread")
        update.start()

    # Display Available Connections Thread
    def sac_thread(self) -> None:
        self.sacThread = Thread(target=self.show_available_connections,
                                name="Show Available Connections Thread")
        # self.sacThread.daemon = True
        self.sacThread.start()

    # Connection History Thread
    def connection_history_thread(self) -> None:
        connhistThread = Thread(target=self.connection_history, name="Connection History Thread")
        connhistThread.start()

    # Disable Controller Buttons Thread
    def disable_buttons_thread(self, sidebar=None) -> None:
        disable = Thread(target=self.disable_buttons,
                         args=(sidebar, ),
                         daemon=True,
                         name="Disable Controller Buttons Thread")
        disable.start()

    # Enable Controller Buttons Thread
    def enable_buttons_thread(self) -> None:
        enable = Thread(target=self.enable_buttons,
                        daemon=True,
                        name="Enable Controller Buttons Thread")
        enable.start()

    # ==++==++==++== END THREADED FUNCS ==++==++==++== #

    # Build initial main frame GUI
    def build_main_window_frames(self) -> None:
        # Sidebar Frame
        self.sidebar_frame = Frame(self, width=150, background="RoyalBlue4")
        self.sidebar_frame.grid(row=0, column=0, sticky="nswe")

        # Main Frame
        self.main_frame = Frame(self, background="ghost white", relief="sunken")
        self.main_frame.configure(border=1)
        self.main_frame.grid(row=0, column=1, sticky="nswe", padx=10)
        self.main_frame.rowconfigure(5, weight=1)
        self.main_frame.columnconfigure(0, weight=1)

        # Main Frame top bar - shows server information
        self.main_frame_top = Frame(self.main_frame, relief='flat')
        self.main_frame_top.grid(row=0, column=0, sticky="nwes")

        # Main frame top bar LabelFrame
        self.top_bar_label = LabelFrame(self.main_frame, text="Server Information", relief='solid')
        self.top_bar_label.grid(row=0, column=0, sticky='news')

        # Table Frame in Main Frame
        self.main_frame_table = Frame(self.main_frame, relief='flat')
        self.main_frame_table.grid(row=1, column=0, sticky="news", pady=2)

        # Controller Frame
        self.controller_frame = Frame(self.main_frame, relief='flat')
        self.controller_frame.grid(row=2, column=0, sticky='news', pady=2)

        # Controller Buttons LabelFrame in Main Frame
        self.controller_btns = LabelFrame(self.controller_frame, text="Controller", relief='solid', height=60)
        self.controller_btns.pack(fill=BOTH)

        # Create Connected Table inside Main Frame when show connected btn pressed
        self.table_frame = LabelFrame(self.main_frame_table, text="Connected Stations")
        self.table_frame.pack(fill=BOTH)

        # Details Frame
        self.details_frame = Frame(self.main_frame, relief='flat')
        self.details_frame.grid(row=3, column=0, sticky='news')

        # Statusbar Frame
        self.statusbar_frame = Frame(self.main_frame, relief='solid', pady=5)
        self.statusbar_frame.grid(row=4, column=0, sticky='news')

        # Status LabelFrame
        self.status_labelFrame = LabelFrame(self.statusbar_frame, height=5, width=900, text='Status', relief='solid',
                                            pady=5)
        self.status_labelFrame.pack(fill=BOTH)
        # self.status_labelFrame.grid(row=5, column=0, sticky='news')

    # Create Sidebar Buttons
    def build_sidebar_buttons(self) -> None:
        # Refresh Button
        self.btn_refresh = tk.Button(self.sidebar_frame,
                                     text="Refresh", width=15, pady=10,
                                     command=lambda: self.refresh())
        self.btn_refresh.grid(row=0, sticky="nwes")
        self.sidebar_buttons.append(self.btn_refresh)

        # Connection History
        self.btn_connection_history = tk.Button(self.sidebar_frame, text="History", width=15, pady=10,
                                                command=lambda: self.connection_history_thread())
        self.btn_connection_history.grid(row=1, sticky='news')
        self.sidebar_buttons.append(self.btn_connection_history)

        # Update Clients Button
        self.btn_update_clients = tk.Button(self.sidebar_frame,
                                            text="Update All Clients", width=15, pady=10,
                                            command=lambda: self.update_all_clients_thread())

        self.btn_update_clients.grid(row=2, sticky="nwes")
        self.sidebar_buttons.append(self.btn_update_clients)

        # EXIT Button
        self.btn_exit = tk.Button(self.sidebar_frame,
                                  text="Exit", width=15, pady=10,
                                  command=lambda: self.exit())
        self.btn_exit.grid(row=3, sticky="nwes")
        self.sidebar_buttons.append(self.btn_exit)

    # Create Treeview Table for connected stations
    def build_connected_table(self) -> None:
        # Create Scrollbar
        self.table_sb = Scrollbar(self.table_frame, orient=VERTICAL)
        self.table_sb.pack(side=LEFT, fill=Y)

        # Create a Table for connected stations
        self.connected_table = ttk.Treeview(self.table_frame,
                                            columns=("ID", "MAC Address",
                                                     "IP Address", "Station Name",
                                                     "Logged User", "Client Version"),
                                            show="headings", height=10,
                                            selectmode='browse', yscrollcommand=self.table_sb.set)
        self.connected_table.pack(fill=BOTH)
        self.table_sb.config(command=self.connected_table.yview)

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
        self.style.theme_use("Details")
        self.style.configure("Treeview", rowheight=20, background="#D3D3D3", foreground="black")
        self.style.map("Treeview", background=[('selected', 'green')])

    # Build Table for Connection History
    def create_connection_history_table(self) -> None:
        # History LabelFrame
        self.history_labelFrame = LabelFrame(self.main_frame, text="Connection History",
                                             relief='ridge')
        self.history_labelFrame.grid(row=3, column=0, sticky='news')
        # self.history_labelFrame.pack()

        # Create Scrollbar
        self.history_table_scrollbar = Scrollbar(self.history_labelFrame, orient=VERTICAL)
        self.history_table_scrollbar.pack(side=LEFT, fill=Y)

        # Create Tree
        self.history_table = ttk.Treeview(self.history_labelFrame,
                                          columns=("ID", "MAC Address",
                                                   "IP Address", "Station Name",
                                                   "Logged User", "Time"),
                                          show="headings", selectmode='none',
                                          yscrollcommand=self.history_table_scrollbar.set)

        self.history_table.config(height=17)
        self.history_table.pack()
        self.history_table_scrollbar.config(command=self.history_table.yview)

        # Columns & Headings config
        self.history_table.column("#1", anchor=CENTER)
        self.history_table.heading("#1", text="ID")
        self.history_table.column("#2", anchor=CENTER)
        self.history_table.heading("#2", text="MAC")
        self.history_table.column("#3", anchor=CENTER)
        self.history_table.heading("#3", text="IP")
        self.history_table.column("#4", anchor=CENTER)
        self.history_table.heading("#4", text="Station Name")
        self.history_table.column("#5", anchor=CENTER)
        self.history_table.heading("#5", text="Logged User")
        self.history_table.column("#6", anchor=CENTER)
        self.history_table.heading("#6", text="Time")

    # Server listener
    def listener(self) -> None:
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.serverIP, self.port))
        self.server.listen()

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

    # Update status bar messages
    def update_statusbar_messages(self, msg=''):
        status_label = Label(self.status_labelFrame, relief='flat',
                             text=f"{msg}\t\t\t\t\t\t\t\t")
        status_label.grid(row=0, column=0, sticky='w')

    # Close App
    def on_closing(self, event=0) -> None:
        self.destroy()

    # ==++==++==++== SIDEBAR BUTTONS ==++==++==++==

    # Refresh server info & connected stations table with vital signs
    def refresh(self) -> None:
        self.disable_buttons_thread(sidebar=False)
        self.tmp_availables = []

        self.vital_signs_thread()
        self.server_information()
        self.show_available_connections()
        self.connection_history()

        # Display Status Message
        self.update_statusbar_messages_thread(msg='Status: refresh complete.')

    # Display Connection History
    def connection_history(self) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running connection_history()...')

        # Clear Selected row in Connected Stations table
        self.show_available_connections()

        # Disable Buttons
        self.disable_buttons_thread(sidebar=False)

        # Display Connection History Table
        self.create_connection_history_table()

        # Update statusbar message
        self.update_statusbar_messages_thread(msg=f'Status: displaying connection history.\t\t\t\t\t\t\t\t\t\t\t\t\t')

        # Create striped row tags
        self.history_table.tag_configure('oddrow', background='white')
        self.history_table.tag_configure('evenrow', background='lightblue')

        c = 0  # Initiate Counter for Connection Number
        try:
            # Iterate Through Connection History List Items
            self.logIt_thread(self.log_path, msg=f'Iterating self.connHistory...')
            for connection in self.connHistory:
                for conKey, macValue in connection.items():
                    for macKey, ipVal in macValue.items():
                        for ipKey, identValue in ipVal.items():
                            for identKey, userValue in identValue.items():
                                for userKey, timeValue in userValue.items():
                                    # Show results in GUI table
                                    if c % 2 == 0:
                                        self.history_table.insert('', 'end', values=(c, macKey, ipKey,
                                                                                     identKey, userKey,
                                                                                     timeValue), tags=('evenrow',))
                                    else:
                                        self.history_table.insert('', 'end', values=(c, macKey, ipKey,
                                                                                     identKey, userKey,
                                                                                     timeValue), tags=('oddrow',))
                        c += 1

            # Enable Controller Buttons
            # self.enable_controller_buttons_thread()
            return True

        # Break If Client Lost Connection
        except (KeyError, socket.error, ConnectionResetError) as e:
            # Update statusbar message
            self.update_statusbar_messages_thread(msg=f'Status: {e}.')
            return False

    # Broadcast update command to all connected stations
    def update_all_clients(self) -> bool:
        self.disable_buttons_thread(sidebar=False)
        # messagebox.showinfo("Update All Clients", "Updating clients, click refresh to view progress.")

        try:
            for t in self.targets:
                t.send('update'.encode())
                t.recv(1024).decode()

        except RuntimeError:
            pass

        self.refresh()
        messagebox.showinfo("Update All Clients", "Update command sent.\nClick refresh to update the connected table.")

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
                self.logIt_thread(self.log_path, debug=True, msg=f'Exiting app with code 1...')
                sys.exit(1)

        self.logIt_thread(self.log_path, msg=f'Exiting app with code 0...')
        self.destroy()
        sys.exit(0)

    # ==++==++==++== CONTROLLER BUTTONS ==++==++==++==
    # Screenshot from Client
    def screenshot(self, con: str, ip: str, sname: str) -> None:
        # Disable Controller Buttons
        self.disable_buttons_thread(sidebar=True)

        # Update statusbar message
        self.update_statusbar_messages_thread(msg=f'Status: fetching screenshot from {ip} | {sname}...')

        try:
            self.logIt_thread(self.log_path, msg=f'Sending screen command to client...')
            con.send('screen'.encode())
            self.logIt_thread(self.log_path, msg=f'Send Completed.')

            self.logIt_thread(self.log_path, msg=f'Calling Module: '
                                                 f'screenshot({con, self.path, self.tmp_availables, self.clients})...')

            scrnshot = screenshot.Screenshot(con, self.path, self.tmp_availables,
                                             self.clients, self.log_path, self.targets)

            self.logIt_thread(self.log_path, msg=f'Calling screenshot.recv_file()...')
            scrnshot.recv_file(ip)

            # Update statusbar message
            self.update_statusbar_messages_thread(msg=f'Status: screenshot received from  {ip} | {sname}.')

            # Display file content in system information notebook TextBox
            self.display_screenshot(fr"{self.path}\{sname}", self.system_information_tab, txt='Screenshot')

            # Enable Controller Buttons
            self.enable_buttons_thread()

        except (WindowsError, socket.error, ConnectionResetError) as e:
            self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')

            # Update statusbar message
            self.update_statusbar_messages_thread(msg=f'Status: {e}.')

            self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip}...)')
            self.remove_lost_connection(con, ip)

    # Run Anydesk on Client
    def anydesk(self, con: str, ip: str, sname: str) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running anydesk({con}, {ip})...')

        # Update statusbar message
        self.update_statusbar_messages_thread(msg=f'Status: running anydesk on {ip} | {sname}...')

        try:
            self.logIt_thread(self.log_path, msg=f'Sending anydesk command to {con}...')
            con.send('anydesk'.encode())
            self.logIt_thread(self.log_path, msg=f'Send Completed.')

            self.logIt_thread(self.log_path, msg=f'Waiting for response from client...')
            msg = con.recv(1024).decode()
            self.logIt_thread(self.log_path, msg=f'Client response: {msg}.')

            if "OK" not in msg:
                self.logIt_thread(self.log_path, msg=f'Printing msg from client...')

                # Update statusbar message
                self.update_statusbar_messages_thread(msg=f'Status: {ip} | {sname}: Anydesk not installed.')

                install_anydesk = messagebox.askyesno("Install Anydesk",
                                                      "Anydesk isn't installed on the remote machine. do you with to install?")

                if install_anydesk:
                    # Update statusbar message
                    self.update_statusbar_messages_thread(msg=f'Status: installing anydesk on {ip} | {sname}...')

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
                            # Update statusbar message
                            self.update_statusbar_messages_thread(msg=f'Status: {msg}')

                        else:
                            # Update statusbar message
                            self.update_statusbar_messages_thread(msg=f'Status: {textVar}')

                            msgBox = messagebox.showinfo(f"From {ip} | {sname}", f"Anydesk Running.\t\t\t\t")

                            # Update statusbar message
                            self.update_statusbar_messages_thread(msg=f'Status: anydesk running on {ip} | {sname}.')

                            return True

                else:
                    self.logIt_thread(self.log_path, msg=f'Sending cancel command to {con}...')
                    con.send('n'.encode())
                    self.logIt_thread(self.log_path, msg=f'Send Completed.')
                    return

            else:
                # Update statusbar message
                self.update_statusbar_messages_thread(msg=f'Status: anydesk running on {ip} | {sname}.')

                msgBox = messagebox.showinfo(f"From {ip} | {sname}", f"Anydesk Running.\t\t\t\t")
                return True

        except (WindowsError, ConnectionError, socket.error, RuntimeError) as e:
            self.logIt_thread(self.log_path, msg=f'Connection Error: {e}.')

            # Update statusbar message
            self.update_statusbar_messages_thread(msg=f'Status: {e}.')
            self.logIt_thread(self.log_path, debug=True,
                              msg=f'Calling self.remove_lost_connection({con}, {ip})...')
            self.remove_lost_connection(con, ip)
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

            # Update statusbar message
            self.update_statusbar_messages_thread(msg=f'Status: restart for {sname}: {msg.split("|")[1][15:]}')

            # Display MessageBox on screen
            messagebox.showinfo(f"Last Restart for: {ip} | {sname}", f"\t{msg.split('|')[1][15:]}\t\t\t")

            return True

        except (WindowsError, socket.error, ConnectionResetError) as e:
            self.logIt_thread(self.log_path, debug=False, msg=f'Connection Error: {e}.')
            # Update statusbar message
            self.update_statusbar_messages_thread(msg=f'Status: {e}')

            try:
                self.logIt_thread(self.log_path, debug=False,
                                  msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                self.remove_lost_connection(con, ip)
                return False

            except RuntimeError as e:
                self.logIt_thread(self.log_path, debug=True, msg=f'Runtime Error: {e}.')
                return False

    # Client System Information
    def sysinfo(self, con: str, ip: str, sname: str):
        # Disable Controller Button
        self.disable_buttons_thread(sidebar=True)

        # Update statusbar message
        self.update_statusbar_messages_thread(msg=f'Status: waiting for system information from {ip} | {sname}...')

        try:
            self.logIt_thread(self.log_path, msg=f'Initializing Module: sysinfo...')
            sinfo = sysinfo.Sysinfo(con, self.ttl, self.path, self.tmp_availables, self.clients, self.log_path, ip)

            self.logIt_thread(self.log_path, msg=f'Calling sysinfo.run()...')
            filepath = sinfo.run(ip)

            # Update statusbar message
            self.update_statusbar_messages_thread(
                msg=f'Status: system information file received from {ip} | {sname}.')

            # Display file content in system information notebook TextBox
            self.display_file_content(filepath, self.system_information_tab, txt='System Information')

            # Enable Controller Buttons
            self.enable_buttons_thread()

        except (WindowsError, socket.error, ConnectionResetError) as e:
            self.logIt_thread(self.log_path, debug=True, msg=f'Connection Error: {e}.')

            # Update statusbar message
            self.update_statusbar_messages_thread(msg=f'Status: {e}.')

            try:
                self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                self.remove_lost_connection(con, ip)

                # Enable Controller Buttons
                self.enable_buttons_thread()
                return

            except RuntimeError:
                # Enable Controller Buttons
                self.enable_buttons_thread()
                return

    # Display/Kill Tasks on Client
    def tasks(self, con: str, ip: str, sname: str) -> bool:
        def what_task() -> str:
            task_to_kill = simpledialog.askstring(parent=self, title='Task To Kill', prompt="Task to kill\t\t\t\t")
            if task_to_kill is None:
                try:
                    con.send('n'.encode())
                    self.enable_buttons_thread()
                    messagebox.showwarning(f"From {ip} | {sname}", "Task Kill canceled.\t\t\t\t\t\t\t\t")
                    return False

                except (WindowsError, socket.error) as e:
                    self.logIt_thread(self.log_path, msg=f'Error: {e}.')
                    self.update_statusbar_messages_thread(msg=f"Status: {e}")
                    self.remove_lost_connection(con, ip)
                    self.enable_buttons_thread()
                    return False

            if len(task_to_kill) == 0:
                try:
                    con.send('n'.encode())
                    self.enable_buttons_thread()
                    messagebox.showwarning(f"From {ip} | {sname}", "Task Kill canceled.\t\t\t\t\t\t\t\t")
                    return False

                except (WindowsError, socket.error) as e:
                    self.logIt_thread(self.log_path, msg=f'Error: {e}.')
                    self.update_statusbar_messages_thread(msg=f"Status: {e}")
                    self.remove_lost_connection(con, ip)
                    self.enable_buttons_thread()
                    return False

            if not str(task_to_kill).endswith('exe'):
                try:
                    con.send('n'.encode())
                    self.enable_buttons_thread()
                    messagebox.showwarning(f"From {ip} | {sname}", "Task Kill canceled.\t\t\t\t\t\t\t\t")
                    return False

                except (WindowsError, socket.error) as e:
                    self.logIt_thread(self.log_path, msg=f'Error: {e}.')
                    self.update_statusbar_messages_thread(msg=f"Status: {e}")
                    self.remove_lost_connection(con, ip)
                    return False

            self.enable_buttons_thread()
            return task_to_kill

        def kill_task(task_to_kill):
            try:
                self.logIt_thread(self.log_path, msg=f'Sending kill command to {ip}.')
                con.send('kill'.encode())
                self.logIt_thread(self.log_path, msg=f'Send complete.')

            except (WindowsError, socket.error) as e:
                self.logIt_thread(self.log_path, msg=f'Error: {e}.')
                self.update_statusbar_messages_thread(msg=f'Status: {e}.')
                self.remove_lost_connection(con, ip)
                return False

            try:
                self.logIt_thread(self.log_path, msg=f'Sending task name to {ip}...')
                con.send(task_to_kill.encode())
                self.logIt_thread(self.log_path, msg=f'Send complete.')

            except (WindowsError, socket.error) as e:
                self.logIt_thread(self.log_path, msg=f'Error: {e}.')
                self.update_statusbar_messages_thread(msg=f'Status: {e}.')
                self.remove_lost_connection(con, ip)
                return False

            try:
                self.logIt_thread(self.log_path, msg=f'Waiting for confirmation from {ip}...')
                msg = con.recv(1024).decode()
                self.logIt_thread(self.log_path, msg=f'{ip}: {msg}')

            except (WindowsError, socket.error) as e:
                self.logIt_thread(self.log_path, msg=f'Error: {e}.')
                self.update_statusbar_messages_thread(msg=f'Status: {e}.')
                self.remove_lost_connection(con, ip)
                return False

            messagebox.showinfo(f"From {ip} | {sname}", f"{msg}.\t\t\t\t\t\t\t\t")

            # Update statusbar message
            self.update_statusbar_messages_thread(msg=f'Status: killed task {task_to_kill} on {ip} | {sname}.')

            # Enable Controller Buttons
            self.enable_buttons_thread()

            return True

        # Disable controller buttons
        self.disable_buttons_thread(sidebar=True)

        # Update statusbar message
        self.update_statusbar_messages_thread(msg=f'Status: running tasks command on {ip} | {sname}.')

        self.logIt_thread(self.log_path, debug=False, msg=f'Initializing Module: tasks...')
        tsks = tasks.Tasks(con, ip, self.clients, self.connections,
                           self.targets, self.ips, self.tmp_availables,
                           self.path, self.log_path, self.path, sname)

        self.logIt_thread(self.log_path, debug=False, msg=f'Calling tasks.tasks()...')
        filepath = tsks.tasks(ip)

        # Display file content in system information notebook TextBox
        self.display_file_content(filepath, self.system_information_tab, txt='Tasks')

        # Display kill task question pop-up
        killTask = messagebox.askyesno(f"Tasks from {ip} | {sname}", "Kill Task?\t\t\t\t\t\t\t\t")
        if killTask:
            task_to_kill = what_task()
            if str(task_to_kill) == '' or str(task_to_kill).startswith(' '):
                self.enable_buttons_thread()
                return Falseq

            if not task_to_kill:
                self.enable_buttons_thread()
                return False

            confirmKill = messagebox.askyesno(f'Kill task: {task_to_kill} on {sname}',
                                              f'Are you sure you want to kill {task_to_kill}?')
            if confirmKill:
                kill_task(task_to_kill)

            else:
                self.logIt_thread(self.log_path, msg=f'Sending pass command to {ip}.')
                try:
                    con.send('pass'.encode())

                except (WindowsError, socket.error) as e:
                    self.update_statusbar_messages_thread(msg=f'Status: {e}.')
                    return False

                return False

        else:
            self.logIt_thread(self.log_path, msg=f'Sending "n" to {ip}.')
            try:
                con.send('n'.encode())
                self.enable_buttons_thread()

            except (WindowsError, socket.error) as e:
                self.logIt_thread(self.log_path, msg=f'Error: {e}.')
                self.update_statusbar_messages_thread(msg=f'Status: {e}.')
                self.remove_lost_connection(con, ip)
                return False

            # Update statusbar message
            self.update_statusbar_messages_thread(msg=f'Status: tasks file received from {ip} | {sname}.')

        # Enable Controller Buttons
        self.enable_buttons_thread()

        return True

    # Restart Client
    def restart(self, con: str, ip: str, sname: str) -> bool:
        # Update statusbar message
        self.update_statusbar_messages_thread(msg=f'Status: waiting for restart confirmation...')

        # Display MessageBox on screen
        self.sure = messagebox.askyesno(f"Restart for: {ip} | {sname}",
                                        f"Are you sure you want to restart {sname}?\t")
        if self.sure:
            try:
                self.logIt_thread(self.log_path, msg=f'Sending restart command to client...')
                con.send('restart'.encode())
                self.remove_lost_connection(con, ip)
                self.refresh()

                # Update statusbar message
                self.update_statusbar_messages_thread(msg=f'Status: restart command sent to {ip} | {sname}.')

                return True

            except (RuntimeError, WindowsError, socket.error) as e:
                self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')

                # Update statusbar message
                self.update_statusbar_messages_thread(msg=f'Status: {e}')

                self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                self.remove_lost_connection(con, ip)

                return False

        else:
            # Update statusbar message
            self.update_statusbar_messages_thread(msg=f'Status: restart canceled.')
            return False

    # Browse local files by Clients Station Names
    def browse_local_files(self, sname: str) -> subprocess:
        return subprocess.Popen(rf"explorer {self.path}\{sname}")

    # ==++==++==++== END Controller Buttons ==++==++==++==

    # # ==++==++==++== Server Processes ==++==++==++==
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
                self.logIt_thread(self.log_path,
                                  msg=f'Adding {self.conn} | {self.ip} to temp live connections dict...')
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

    # Convert bytes to numbers for file transfers
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

    # Log & Debugger
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

    # Check if connected stations are still connected
    def vital_signs(self) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running vital_signs()...')
        if len(self.targets) == 0:
            self.update_statusbar_messages_thread(msg='Status: No connected stations.')
            # messagebox.showinfo("Refresh", "No Connected Stations.")
            return False

        callback = 'yes'
        i = 0

        # Update statusbar message
        self.update_statusbar_messages_thread(msg=f'Status: running vitals check...')

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
                                            # Update statusbar message
                                            self.update_statusbar_messages_thread(
                                                msg=f'Status: Station IP: {self.ips[i]} | Station Name: {v} | Client Version: {ver} - ALIVE!')
                                            i += 1
                                            time.sleep(0.5)

                except (IndexError, RuntimeError):
                    pass

            else:
                for conKey, macValue in self.clients.items():
                    for con in self.targets:
                        if conKey == con:
                            for macKey, ipVal in macValue.items():
                                for ipKey, identValue in ipVal.items():
                                    if ipKey == self.ips[i]:
                                        self.remove_lost_connection(conKey, ipKey)

        self.logIt_thread(self.log_path, msg=f'=== End of vital_signs() ===')

        # Update statusbar message
        self.update_statusbar_messages_thread(msg=f'Status: Vitals check completed.')

        return True

    # Display Available Connections
    def show_available_connections(self) -> None:
        self.logIt_thread(self.log_path, msg=f'Running show_available_connections()...')
        if len(self.ips) == 0 and len(self.targets) == 0:
            self.logIt_thread(self.log_path, msg=f'No connected Stations')

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
            # Create striped row tags
            self.connected_table.tag_configure('oddrow', background='white')
            self.connected_table.tag_configure('evenrow', background='lightblue')

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
                                if session % 2 == 0:
                                    self.connected_table.insert('', 'end', values=(session, stationMAC, stationIP,
                                                                                   stationName, loggedUser,
                                                                                   clientVersion), tags=('evenrow',))
                                else:
                                    self.connected_table.insert('', 'end', values=(session, stationMAC, stationIP,
                                                                                   stationName, loggedUser,
                                                                                   clientVersion), tags=('oddrow',))

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

    # Shell Connection to Client
    def shell(self, con: str, ip: str, sname: str) -> None:
        self.logIt_thread(self.log_path, msg=f'Running shell({con}, {ip})...')

        # Update statusbar message
        self.update_statusbar_messages_thread(msg=f'Status: shell connected to {ip} | {sname}.')

        while True:
            self.logIt_thread(self.log_path, msg=f'Calling self.show_shell_commands({ip})...')

            # Wait for User Input & hide print
            self.logIt_thread(self.log_path, msg=f'Waiting for user input...')
            cmd = input(f"")

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

                                    # Update statusbar message
                                    self.update_statusbar_messages_thread(
                                        msg=f'Status: {ip} | {identValue} | {userValue} removed from connected list.')

            self.logIt_thread(self.log_path, msg=f'Connections removed.')
            return True

        except RuntimeError as e:
            self.logIt_thread(self.log_path, msg=f'Runtime Error: {e}.')
            return False

    # Enable Controller Buttons
    def enable_buttons(self):
        for button in list(self.buttons):
            button.config(state=NORMAL)

        for sbutton in list(self.sidebar_buttons):
            sbutton.config(state=NORMAL)

    # Disable Controller Buttons
    def disable_buttons(self, sidebar=None):
        if sidebar:
            for button in list(self.buttons):
                button.config(state=DISABLED)

            for sbutton in list(self.sidebar_buttons):
                sbutton.config(state=DISABLED)

            return

        else:
            for button in list(self.buttons):
                button.config(state=DISABLED)

            return

    # Display file content in notebook
    def display_file_content(self, filepath: str, tab: str, txt=''):
        with open(filepath, 'r') as file:
            data = file.read()
            tab = Frame(self.notebook, height=350)

            # Create Tasks Scrollbar
            self.tab_scrollbar = Scrollbar(tab, orient=VERTICAL)
            self.tab_scrollbar.pack(side=LEFT, fill=Y)

            # Create Tasks Textbox
            self.tab_textbox = Text(tab, yscrollcommand=self.tab_scrollbar.set)
            self.tab_textbox.pack(fill=BOTH)

            # Add tab to notebook
            self.notebook.add(tab, text=f"{txt}")

            self.tab_scrollbar.configure(command=self.tab_textbox.yview)
            self.tab_textbox.config(state=NORMAL)
            self.tab_textbox.delete(1.0, END)
            self.tab_textbox.insert(END, data)
            self.tab_textbox.config(state=DISABLED)

            # Display Last Tab
            self.notebook.select(tab)

    # Display Image slider with screenshots
    def display_screenshot(self, path: str, tab: str, txt=''):
        # Sort folder for .jpg files and last creation time
        images = glob.glob(fr"{path}\*.jpg")
        images.sort(key=os.path.getmtime)

        # Last Screenshot
        self.sc = PIL.Image.open(images[-1])
        self.sc_resized = self.sc.resize((650, 350))
        self.last_screenshot = ImageTk.PhotoImage(self.sc_resized)

        # tab = [Frame(self.notebook, height=350) * 10]
        tab = Frame(self.notebook, height=350)
        self.canvas = Canvas(tab, height=350)
        self.canvas.pack(fill=BOTH, padx=10)

        # Add tab to notebook
        self.notebook.add(tab, text=f"{txt}")
        self.notebook_tabs.append(self.notebook.tab(0, "text"))

        # Display Last Screenshot file
        self.canvas.create_image(650, 150, image=self.last_screenshot)

        # Display Last Tab
        self.notebook.select(tab)

        self.remove_tabs(tab)

    # Remove empty screenshot tab from notebook
    def remove_tabs(self, tab):
        for t, ta in zip(self.notebook.tabs(), self.notebook.winfo_children()):
            if self.notebook.tab(tab, "text") == self.notebook.tab(t, "text"):
                self.counter += 1
                print("YAY", self.counter)

            else:
                print(self.notebook.tab(t, "text"), self.counter - 1)

        return True

    # Define GUI Styles
    def make_style(self):
        self.style.theme_create("Details", parent='alt', settings={
            "TNotebook": {"configure": {"tabmargins": [2, 5, 2, 0]}},
            "TNotebook.Tab": {
                "configure": {"padding": [5, 1], "background": 'white'},
                "map": {"background": [("selected", 'green')],
                        "expand": [("selected", [1, 1, 1, 0])]}}})

        self.style.configure("Treeview", rowheight=20, background="#D3D3D3", foreground="black")
        self.style.map("Treeview", background=[('selected', 'green')])

    # Build Notebook
    def create_notebook(self):
        self.style.theme_use("Details")

        # Create Notebook
        self.notebook = ttk.Notebook(self.details_labelFrame, height=330)
        self.notebook.pack(expand=True, pady=5, fill=X)

        self.clear_tabs = Button(self.details_labelFrame, text="Clear Tabs", pady=1)
        self.clear_tabs.pack(anchor=W, padx=5, ipadx=2, ipady=2)

        # Create Tabs
        self.screenshot_tab = Frame(self.notebook, height=330)
        self.system_information_tab = Frame(self.notebook, height=330)
        self.tasks_tab = Frame(self.notebook, height=330)

        # Create System Information Scrollbar
        self.system_scrollbar = Scrollbar(self.system_information_tab, orient=VERTICAL)
        self.system_scrollbar.pack(side=LEFT, fill=Y)

        # Create System Information Textbox
        self.system_information_textbox = Text(self.system_information_tab, yscrollcommand=self.system_scrollbar.set)
        self.system_information_textbox.pack(fill=BOTH)

        # Create Tasks Scrollbar
        self.tasks_scrollbar = Scrollbar(self.tasks_tab, orient=VERTICAL)
        self.tasks_scrollbar.pack(side=LEFT, fill=Y)

        # Create Tasks Textbox
        self.tasks_tab_textbox = Text(self.tasks_tab, yscrollcommand=self.tasks_scrollbar.set)
        self.tasks_tab_textbox.pack(fill=X)

        # Add tabs to notebook
        # self.notebook.add(self.screenshot_tab, text="Screenshot")
        # self.notebook.add(self.system_information_tab, text="System Information")
        # self.notebook.add(self.tasks_tab, text="Tasks")

    # Manage Connected Table & Controller LabelFrame Buttons
    def selectItem(self, event) -> bool:
        # Create Controller Buttons
        def make_buttons():
            # Screenshot Button
            self.screenshot_btn = Button(self.controller_btns, text="Screenshot", width=15, pady=5,
                                         command=lambda: screenshot_thread(clientConn, clientIP, sname))
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
                                      command=lambda: client_system_information_thread(clientConn, clientIP, sname))

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

        def client_system_information_thread(con: str, ip: str, sname: str):
            clientSystemInformationThread = Thread(target=self.sysinfo, args=(con, ip, sname),
                                                   name="Client System Information Thread")
            clientSystemInformationThread.daemon = True
            clientSystemInformationThread.start()

        def screenshot_thread(con: str, ip: str, sname: str):
            screenThread = Thread(target=self.screenshot, args=(con, ip, sname), name='Screenshot Thread')
            screenThread.daemon = True
            screenThread.start()

        # Respond to mouse clicks on connected table
        rowid = self.connected_table.identify_row(event.y)
        row = self.connected_table.item(rowid)['values']

        try:
            if not row[2] in self.temp.values():
                self.temp[row[0]] = row[2]

        # Error can raise when clicking on empty space so the row is None or empty.
        except IndexError:
            pass

        # Display Details LabelFrame
        self.details_labelFrame = LabelFrame(self.main_frame, text="Details", relief='ridge',
                                             height=400, background='light grey')
        self.details_labelFrame.grid(row=3, sticky='news', columnspan=3)

        self.create_notebook()

        # Create a Controller LabelFrame with Buttons and connect shell by TreeView Table selection
        for id, ip in self.temp.items():
            for clientConn, clientValues in self.clients.items():
                for clientMac, clientIPv in clientValues.items():
                    for clientIP, vals in clientIPv.items():
                        if clientIP == ip:
                            for sname in vals.keys():
                                make_buttons()
                                self.enable_buttons_thread()

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
