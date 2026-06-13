"""
CPU 异常监控器 
"""

import os
import sys
import ctypes
import threading
import time
from datetime import datetime

import psutil
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import winreg

import pystray
from PIL import Image, ImageDraw, ImageFont

# -------------------------- 自动提权 --------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(f'"{arg}"' for arg in sys.argv), None, 1
    )
    sys.exit(0)

# -------------------------- 常量 --------------------------
APP_NAME = "CPUMonitor"
REG_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
DEFAULT_THRESHOLD = 80
DEFAULT_INTERVAL = 2
DEFAULT_COOLDOWN = 30
TOP_PROCESS_COUNT = 5

# -------------------------- 图标加载 --------------------------
def get_icon_image():
    
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    ico_path = os.path.join(base_dir, "123.ico")
    if not os.path.isfile(ico_path):
        try:
            base_dir = sys._MEIPASS
            ico_path = os.path.join(base_dir, "123.ico")
        except:
            pass

    if os.path.isfile(ico_path):
        try:
            img = Image.open(ico_path)
            return img
        except Exception as e:
            print(f"[图标] 加载失败：{e}")


    img = Image.new('RGB', (64, 64), color='red')
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 36)
    except:
        font = ImageFont.load_default()
    bbox = draw.textbbox((0, 0), "123", font=font)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text(((64 - w) / 2, (64 - h) / 2), "123", fill='white', font=font)
    return img

# -------------------------- 自启动 --------------------------
def is_startup_enabled():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, APP_NAME)
        winreg.CloseKey(key)
        return sys.argv[0] in value
    except FileNotFoundError:
        return False

def set_startup(enable: bool):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_SET_VALUE)
        if enable:
            cmd = f'"{sys.argv[0]}" --tray'
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, cmd)
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"自启动设置失败: {e}")
        return False

# -------------------------- 进程侦查 --------------------------
def get_process_details(proc):
    details = {
        'name': proc.name(),
        'pid': proc.pid,
        'cpu': 0,
        'exe_path': '',
        'file_size': 'N/A',
        'file_size_kb': 0,
        'file_mtime': 'N/A',
        'file_ctime': 'N/A',
        'suspicious': False
    }
    try:
        details['cpu'] = proc.cpu_percent()
        exe_path = proc.exe()
        details['exe_path'] = exe_path
        try:
            stat = os.stat(exe_path)
            size_kb = stat.st_size / 1024
            details['file_size_kb'] = size_kb
            details['file_size'] = f"{size_kb:.1f} KB"
            details['file_mtime'] = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            details['file_ctime'] = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        except OSError:
            pass
        path_low = exe_path.lower()
        suspicious_keywords = ['\\temp\\', '\\downloads\\', '\\appdata\\local\\temp\\']
        details['suspicious'] = any(k in path_low for k in suspicious_keywords)
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        details['exe_path'] = '(无法获取路径)'
    return details

# -------------------------- 监控核心 --------------------------
class CPUMonitor:
    def __init__(self, threshold=DEFAULT_THRESHOLD, interval=DEFAULT_INTERVAL,
                 cooldown=DEFAULT_COOLDOWN, callback_update_ui=None, callback_log=None):
        self.threshold = threshold
        self.interval = interval
        self.cooldown = cooldown
        self.callback_update_ui = callback_update_ui
        self.callback_log = callback_log
        self._stop_event = threading.Event()
        self._last_alert = 0
        self._thread = None

    def _get_top_processes(self, count=TOP_PROCESS_COUNT):
        proc_list = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                cpu = proc.cpu_percent()
                if cpu is not None and cpu > 0:
                    proc_list.append((cpu, proc))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        proc_list.sort(reverse=True, key=lambda x: x[0])
        top = []
        for cpu, proc in proc_list[:count]:
            d = get_process_details(proc)
            d['cpu'] = cpu
            top.append(d)
        return top

    def _format_log_message(self, cpu_percent, processes):
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        lines = []
        lines.append(f"[{now_str}] ⚠ CPU 占用异常：{cpu_percent:.1f}%")
        lines.append("高占用进程：")
        lines.append("-" * 90)
        header = f"{'程序名':<20}{'CPU%':<8}{'大小(KB)':<12}{'创建时间':<20}{'路径'}"
        lines.append(header)
        lines.append("-" * 90)
        for p in processes:
            name = p['name'][:19]
            cpu = f"{p['cpu']:.1f}"
            size = f"{p['file_size_kb']:.1f}" if isinstance(p.get('file_size_kb'), (int, float)) else "N/A"
            ctime = p['file_ctime'] if p['file_ctime'] else "N/A"
            path = p['exe_path'] if p['exe_path'] else "(未知)"
            suspicious = " [⚠可疑]" if p['suspicious'] else ""
            lines.append(f"{name:<20}{cpu:<8}{size:<12}{ctime:<20}{path}{suspicious}")
        lines.append("-" * 90 + "\n")
        return "\n".join(lines)

    def _show_warning(self, cpu_percent, processes):
        proc_short = "\n".join(
            [f"• {p['name']} (PID {p['pid']}) - CPU {p['cpu']:.1f}%" for p in processes[:3]]
        )
        top = tk.Tk()
        top.withdraw()
        top.attributes('-topmost', True)
        top.focus_force()
        top.lift()
        messagebox.showwarning(
            title="⚠️ CPU 占用异常警告",
            message=f"CPU 占用已达 {cpu_percent:.1f}%！\n\n"
                    f"{proc_short}\n\n"
                    f"详细进程信息请查看主界面“异常日志”窗口。",
            parent=top
        )
        top.destroy()

    def _run(self):
        while not self._stop_event.is_set():
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                if self.callback_update_ui:
                    self.callback_update_ui(cpu_percent)

                if cpu_percent >= self.threshold:
                    now = time.time()
                    if now - self._last_alert >= self.cooldown:
                        top_procs = self._get_top_processes()
                        log_msg = self._format_log_message(cpu_percent, top_procs)
                        if self.callback_log:
                            self.callback_log(log_msg)
                        threading.Thread(
                            target=self._show_warning,
                            args=(cpu_percent, top_procs),
                            daemon=True
                        ).start()
                        self._last_alert = now

                for _ in range(int(self.interval * 2)):
                    if self._stop_event.is_set():
                        break
                    time.sleep(0.5)

            except Exception as e:
                print(f"[监控错误] {e}")
                time.sleep(5)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

# -------------------------- 完整主界面 --------------------------
class App:
    def __init__(self, start_in_tray=False):
        self.start_in_tray = start_in_tray
        self.root = tk.Tk()
        self.root.title("CPU 异常监控器")
        self.root.geometry("850x650")
        self.root.configure(bg='black')
        self.root.resizable(True, True)

        from PIL import ImageTk
        self._tk_icon = ImageTk.PhotoImage(get_icon_image())
        self.root.iconphoto(True, self._tk_icon)

        self.monitor = None
        self._status_var = tk.StringVar(value="准备就绪")

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.tray_icon = None
        self._create_tray()

        if self.start_in_tray:
            self.root.withdraw()

    def _build_ui(self):
        # ===== 顶部操作面板 =====
        panel = tk.Frame(self.root, bg='black')
        panel.pack(side='top', fill='x', padx=10, pady=5)

        set_frame = tk.LabelFrame(panel, text="监控设置", bg='black', fg='red',
                                  font=('Microsoft YaHei', 9, 'bold'), padx=10, pady=10)
        set_frame.pack(side='left', fill='x', expand=True, padx=5)

        tk.Label(set_frame, text="CPU 阈值 (%)：", bg='black', fg='red').grid(row=0, column=0, sticky='w', pady=2)
        self.threshold_var = tk.IntVar(value=DEFAULT_THRESHOLD)
        tk.Spinbox(set_frame, from_=10, to=100, textvariable=self.threshold_var, width=5,
                   bg='black', fg='red', buttonbackground='gray20', insertbackground='red').grid(row=0, column=1, sticky='w')

        tk.Label(set_frame, text="检查间隔 (秒)：", bg='black', fg='red').grid(row=1, column=0, sticky='w', pady=2)
        self.interval_var = tk.IntVar(value=DEFAULT_INTERVAL)
        tk.Spinbox(set_frame, from_=1, to=30, textvariable=self.interval_var, width=5,
                   bg='black', fg='red', buttonbackground='gray20', insertbackground='red').grid(row=1, column=1, sticky='w')

        tk.Label(set_frame, text="弹窗冷却 (秒)：", bg='black', fg='red').grid(row=2, column=0, sticky='w', pady=2)
        self.cooldown_var = tk.IntVar(value=DEFAULT_COOLDOWN)
        tk.Spinbox(set_frame, from_=10, to=600, textvariable=self.cooldown_var, width=5,
                   bg='black', fg='red', buttonbackground='gray20', insertbackground='red').grid(row=2, column=1, sticky='w')

        self.startup_var = tk.BooleanVar(value=is_startup_enabled())
        tk.Checkbutton(set_frame, text="开机自启动", variable=self.startup_var, command=self._toggle_startup,
                       bg='black', fg='red', selectcolor='black', activebackground='black',
                       activeforeground='red').grid(row=3, column=0, columnspan=2, sticky='w', pady=5)

        ctrl_frame = tk.Frame(panel, bg='black')
        ctrl_frame.pack(side='left', padx=20)

        self.btn_start = tk.Button(ctrl_frame, text="启动监控", command=self._start_monitor,
                                   bg='#333333', fg='red', activebackground='#555555', activeforeground='red',
                                   relief='flat', padx=10, pady=2)
        self.btn_start.pack(side='top', pady=2)

        self.btn_stop = tk.Button(ctrl_frame, text="停止监控", command=self._stop_monitor, state='disabled',
                                  bg='#333333', fg='red', activebackground='#555555', activeforeground='red',
                                  relief='flat', padx=10, pady=2)
        self.btn_stop.pack(side='top', pady=2)

        self.btn_export = tk.Button(ctrl_frame, text="导出日志", command=self._export_log,
                                    bg='#333333', fg='red', activebackground='#555555', activeforeground='red',
                                    relief='flat', padx=10, pady=2)
        self.btn_export.pack(side='top', pady=2)

        self.cpu_label = tk.Label(panel, text="当前 CPU：-- %", bg='black', fg='red',
                                  font=('Consolas', 12, 'bold'))
        self.cpu_label.pack(side='right', padx=20)

        # ===== 底部日志窗口 =====
        log_frame = tk.Frame(self.root, bg='black')
        log_frame.pack(side='bottom', fill='both', expand=True, padx=10, pady=5)

        tk.Label(log_frame, text="异常日志（点击“导出日志”保存）", bg='black', fg='red',
                 font=('Microsoft YaHei', 9, 'bold')).pack(anchor='w')

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap='none',
            bg='black',
            fg='red',
            insertbackground='red',
            selectbackground='#660000',
            selectforeground='red',
            font=('Consolas', 9),
            state='disabled'
        )
        self.log_text.pack(fill='both', expand=True)
        self._append_log("程序已启动，等待监控...\n")

    def _create_tray(self):
        image = get_icon_image()
        menu = pystray.Menu(
            pystray.MenuItem("显示窗口", self._show_window),
            pystray.MenuItem("退出", self._quit_app)
        )
        self.tray_icon = pystray.Icon("cpu_monitor", image, "CPU异常监控器", menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def _show_window(self, icon=None, item=None):
        self.root.after(0, self.root.deiconify)

    def _quit_app(self, icon=None, item=None):
    
        self._stop_monitor()
        
        if self.tray_icon:
            self.tray_icon.stop()
    
        self.root.after(0, self.root.destroy)
    
        self.root.after(100, lambda: os._exit(0))

    def _toggle_startup(self):
        if self.startup_var.get():
            if not set_startup(True):
                messagebox.showerror("错误", "开机自启动设置失败，可能需要管理员权限。")
                self.startup_var.set(False)
        else:
            set_startup(False)

    def _update_cpu_display(self, value):
        self.cpu_label.config(text=f"当前 CPU：{value:.1f} %")

    def _append_log(self, text):
        self.log_text.config(state='normal')
        self.log_text.insert('end', text)
        self.log_text.see('end')
        self.log_text.config(state='disabled')

    def _start_monitor(self):
        self.monitor = CPUMonitor(
            threshold=self.threshold_var.get(),
            interval=self.interval_var.get(),
            cooldown=self.cooldown_var.get(),
            callback_update_ui=lambda v: self.root.after(0, self._update_cpu_display, v),
            callback_log=lambda msg: self.root.after(0, self._append_log, msg)
        )
        self.monitor.start()
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')
        self._append_log("▶ 监控已启动\n")

    def _stop_monitor(self):
        if self.monitor:
            self.monitor.stop()
            self.monitor = None
        self.cpu_label.config(text="当前 CPU：-- %")
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled')
        self._append_log("■ 监控已停止\n")

    def _export_log(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("日志文件", "*.log"), ("文本文件", "*.txt"), ("所有文件", "*.*")],
            title="导出异常日志"
        )
        if not file_path:
            return
        try:
            content = self.log_text.get('1.0', 'end-1c')
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("导出成功", f"日志已保存至：\n{file_path}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    def _on_close(self):
        self.root.withdraw()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    if not is_admin():
        run_as_admin()

    try:
        import psutil, pystray, PIL
    except ImportError:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("缺少依赖", "请先安装必要模块：pip install psutil pystray pillow")
        sys.exit(1)

    start_tray = '--tray' in sys.argv
    app = App(start_in_tray=start_tray)
    app.run()