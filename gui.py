import tkinter as tk
from tkinter import ttk, scrolledtext
import json
import mmap
import os
import platform
import time
import posix_ipc
import sys

SHARED_MEM_FILE = '/tmp/sysmon_shared_mem'
SHARED_MEM_SIZE = 10 * 1024  # 10 KB

SEM_REQUEST_NAME = "/sysmon_request_sem"
SEM_RESPONSE_NAME = "/sysmon_response_sem"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("System Monitor")
        self.geometry("900x700")
        self.create_widgets()

        if platform.system().lower() != 'linux':
            print("This client works only on Linux.")
            sys.exit(1)

        if not os.path.exists(SHARED_MEM_FILE):
            print("Shared memory file not found.")
            sys.exit(1)

        self.mm_file = open(SHARED_MEM_FILE, 'r+b')
        self.mm = mmap.mmap(self.mm_file.fileno(), SHARED_MEM_SIZE)

        self.sem_request = posix_ipc.Semaphore(SEM_REQUEST_NAME)
        self.sem_response = posix_ipc.Semaphore(SEM_RESPONSE_NAME)

    def send_request(self, command, data=None):
        request_data = {'command': command}
        if data:
            request_data['data'] = data
        request_json = json.dumps(request_data, ensure_ascii=False)

        self.mm.seek(0)
        self.mm.write(request_json.encode('utf-8'))
        self.mm.write(b'\x00' * (SHARED_MEM_SIZE - len(request_json)))

        self.sem_request.release()

        if not self.sem_response.acquire(timeout=10):
            return {'error': 'Timeout waiting for response'}

        self.mm.seek(0)
        raw = self.mm.read(SHARED_MEM_SIZE)
        raw = raw.split(b'\x00', 1)[0]
        response_json = raw.decode('utf-8')

        try:
            response = json.loads(response_json)
        except json.JSONDecodeError:
            response = {'error': 'Invalid JSON response'}

        return response

    def create_widgets(self):
        notebook = ttk.Notebook(self)
        notebook.pack(expand=True, fill='both')

        self.process_frame = ttk.Frame(notebook)
        notebook.add(self.process_frame, text="Processes")
        self.create_process_tab()

        self.gpu_frame = ttk.Frame(notebook)
        notebook.add(self.gpu_frame, text="GPU Info")
        self.create_gpu_tab()

        self.file_creation_frame = ttk.Frame(notebook)
        notebook.add(self.file_creation_frame, text="File Creation")
        self.create_file_creation_tab()

        self.uptime_frame = ttk.Frame(notebook)
        notebook.add(self.uptime_frame, text="Uptime")
        self.create_uptime_tab()

        self.network_frame = ttk.Frame(notebook)
        notebook.add(self.network_frame, text="Network Config")
        self.create_network_tab()

        self.terminal_frame = ttk.Frame(notebook)
        notebook.add(self.terminal_frame, text="Terminal")
        self.create_terminal_tab()

    def create_process_tab(self):
        btn = ttk.Button(self.process_frame, text="Get Processes", command=self.get_processes)
        btn.pack(pady=5)

        columns = ("pid", "name", "username")
        self.process_table = ttk.Treeview(self.process_frame, columns=columns, show='headings')
        self.process_table.heading("pid", text="PID")
        self.process_table.heading("name", text="Name")
        self.process_table.heading("username", text="User")
        self.process_table.column("pid", width=80, anchor='center')
        self.process_table.column("name", width=300)
        self.process_table.column("username", width=200)
        self.process_table.pack(expand=True, fill='both', padx=10, pady=10)

        scrollbar = ttk.Scrollbar(self.process_frame, orient="vertical", command=self.process_table.yview)
        self.process_table.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

    def create_gpu_tab(self):
        btn = ttk.Button(self.gpu_frame, text="Get GPU Info", command=self.get_gpu_info)
        btn.pack(pady=5)

        self.gpu_text = scrolledtext.ScrolledText(self.gpu_frame, wrap=tk.WORD)
        self.gpu_text.pack(expand=True, fill='both', padx=10, pady=10)

    def create_file_creation_tab(self):
        btn = ttk.Button(self.file_creation_frame, text="Detect File Creation", command=self.detect_file_creation)
        btn.pack(pady=5)

        self.file_creation_text = scrolledtext.ScrolledText(self.file_creation_frame, wrap=tk.WORD)
        self.file_creation_text.pack(expand=True, fill='both', padx=10, pady=10)

    def create_uptime_tab(self):
        btn = ttk.Button(self.uptime_frame, text="Get Uptime", command=self.get_uptime)
        btn.pack(pady=5)

        self.uptime_label = ttk.Label(self.uptime_frame, text="", font=("Arial", 14))
        self.uptime_label.pack(pady=20)

    def create_network_tab(self):
        btn = ttk.Button(self.network_frame, text="Get Network Config", command=self.get_network_config)
        btn.pack(pady=5)

        self.network_text = scrolledtext.ScrolledText(self.network_frame, wrap=tk.WORD)
        self.network_text.pack(expand=True, fill='both', padx=10, pady=10)

    def create_terminal_tab(self):
        label = ttk.Label(self.terminal_frame, text="Enter Command:")
        label.pack(pady=5)

        self.command_entry = ttk.Entry(self.terminal_frame, width=80)
        self.command_entry.pack(pady=5)

        run_btn = ttk.Button(self.terminal_frame, text="Run Command", command=self.run_command)
        run_btn.pack(pady=5)

        self.output_text = scrolledtext.ScrolledText(self.terminal_frame, wrap=tk.WORD)
        self.output_text.pack(expand=True, fill='both', padx=10, pady=10)

    def get_processes(self):
        response = self.send_request('get_processes')
        if 'error' in response:
            self.show_error(self.process_table, response['error'])
            return
        for row in self.process_table.get_children():
            self.process_table.delete(row)
        for proc in response:
            pid = proc.get('pid', '')
            name = proc.get('name', '')
            user = proc.get('username', '')
            self.process_table.insert('', 'end', values=(pid, name, user))

    def get_gpu_info(self):
        response = self.send_request('get_gpu_info')
        if 'error' in response:
            self.gpu_text.delete(1.0, tk.END)
            self.gpu_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.gpu_text.delete(1.0, tk.END)
        if isinstance(response, list):
            self.gpu_text.insert(tk.END, '\n'.join(response))
        else:
            self.gpu_text.insert(tk.END, str(response))

    def detect_file_creation(self):
        response = self.send_request('detect_file_creation')
        if 'error' in response:
            self.file_creation_text.delete(1.0, tk.END)
            self.file_creation_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.file_creation_text.delete(1.0, tk.END)
        if isinstance(response, list):
            self.file_creation_text.insert(tk.END, '\n'.join(response))
        else:
            self.file_creation_text.insert(tk.END, str(response))

    def get_uptime(self):
        response = self.send_request('get_uptime')
        if 'error' in response:
            self.uptime_label.config(text=f"Error: {response['error']}")
            return
        self.uptime_label.config(text=str(response))

    def get_network_config(self):
        response = self.send_request('get_network_config')
        if 'error' in response:
            self.network_text.delete(1.0, tk.END)
            self.network_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.network_text.delete(1.0, tk.END)
        self.network_text.insert(tk.END, response)

    def run_command(self):
        command = self.command_entry.get()
        response = self.send_request('execute_command', data=command)
        self.output_text.delete(1.0, tk.END)
        if isinstance(response, dict) and 'error' in response:
            self.output_text.insert(tk.END, f"Error: {response['error']}")
        else:
            self.output_text.insert(tk.END, response)

    def show_error(self, widget, message):
        if isinstance(widget, ttk.Treeview):
            for row in widget.get_children():
                widget.delete(row)
            widget.insert('', 'end', values=(message,))
        else:
            widget.delete(1.0, tk.END)
            widget.insert(tk.END, message)

if __name__ == "__main__":
    app = App()
    app.mainloop()
