import os
import zipfile
import shutil
import tempfile
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.filedialog import askopenfilename, asksaveasfilename, askdirectory
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import tkinterdnd2
import datetime
import atexit
import secrets
import json
import string
import webbrowser
import threading
import sys
import glob

# 增加递归深度限制
sys.setrecursionlimit(10000)

# 语言管理
class LanguageManager:
    def __init__(self):
        self.current_lang = None
        self.strings = {}
        self.load_languages()
        
    def load_languages(self):
        self.available_langs = {}
        lang_path = os.path.join(os.path.dirname(__file__), 'lang')
        for lang_file in glob.glob(os.path.join(lang_path, '*.json')):
            lang_code = os.path.splitext(os.path.basename(lang_file))[0]
            with open(lang_file, 'r', encoding='utf-8') as f:
                self.available_langs[lang_code] = json.load(f)
                
        # 默认使用中文
        self.set_language('zh_cn')
        
    def set_language(self, lang_code):
        if lang_code in self.available_langs:
            self.current_lang = lang_code
            self.strings = self.available_langs[lang_code]
            
    def get_string(self, key, *args):
        if key not in self.strings:
            return key
        text = self.strings[key]
        if args:
            text = text.format(*args)
        return text

# 全局语言管理器
lang_mgr = LanguageManager()

def get_file_icon(filename):
    """根据文件后缀返回对应图标"""
    ext = os.path.splitext(filename)[1].lower()
    
    # 图片文件
    if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
        return '🖼️'
    # 视频文件    
    elif ext in ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv']:
        return '🎥'
    # 音频文件
    elif ext in ['.mp3', '.wav', '.ogg', '.m4a', '.flac']:
        return '🎵'
    # 压缩文件
    elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
        return '📦'
    # 文档文件
    elif ext in ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx']:
        return '📄'
    # 可执行文件
    elif ext in ['.exe', '.msi', '.bat']:
        return '🪟'
    # 代码文件
    elif ext in ['.py', '.java', '.cpp', '.js', '.html', '.css','dat']:
        return '📝'
    # DLL和系统文件
    elif ext in ['.dll', '.sys', '.drv', '.ocx']:
        return '🔧'
    # 邮件和消息文件
    elif ext in ['.msg', '.eml', '.pst', '.ost', '.mbox']:
        return '📫'
    # 网页和样式文件
    elif ext in ['.html', '.htm', '.css', '.js', '.php', '.asp', '.jsp']:
        return '🌐'
    # 字体文件
    elif ext in ['.ttf', '.otf', '.woff', '.woff2', '.eot']:
        return '🔤'
    # 数据库文件
    elif ext in ['.db', '.sqlite', '.mdb', '.accdb']:
        return '💾'
    # 配置文件
    elif ext in ['.ini', '.cfg', '.conf', '.json', '.xml', '.yaml', '.yml']:
        return '⚙️'
    # 文件夹
    elif os.path.isdir(filename):
        return '📁'
    # 其他文件
    else:
        return '📄'

def long_path(path):
    if os.name == 'nt' and not path.startswith('\\\\?\\'):
        path = os.path.abspath(path)
        return '\\\\?\\' + path
    return path

def normalize_path(path):
    if path.startswith('\\\\?\\'):
        return path[4:]
    return path

def get_file_info(path):
    stat = os.stat(path)
    size = stat.st_size
    mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
    
    if size < 1024:
        size_str = lang_mgr.get_string('SIZE.B', size)
    elif size < 1024 * 1024:
        size_str = lang_mgr.get_string('SIZE.KB', f"{size/1024:.1f}")
    else:
        size_str = lang_mgr.get_string('SIZE.MB', f"{size/1024/1024:.1f}")
        
    time_str = mtime.strftime("%Y-%m-%d %H:%M:%S")
    
    return size_str, time_str

def encrypt_file(file_path, password):
    """
    使用高强度加密算法加密文件
    """
    salt = secrets.token_bytes(32)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,  # 增加迭代次数
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    iv = secrets.token_bytes(16)
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    with open(file_path, 'rb') as f:
        data = f.read()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    password_hash = base64.b64encode(password.encode()).decode()
    metadata = json.dumps({"password": password_hash}).encode()
    
    with open(file_path, 'wb') as f:
        metadata_len = len(metadata).to_bytes(4, byteorder='big')
        f.write(metadata_len + metadata + salt + iv + encrypted_data)

def decrypt_file(file_path, password=None):
    """
    解密文件
    """
    with open(file_path, 'rb') as f:
        metadata_len = int.from_bytes(f.read(4), byteorder='big')
        metadata = json.loads(f.read(metadata_len))
        if password:
            stored_password = base64.b64decode(metadata["password"]).decode()
            if password != stored_password:
                raise ValueError(lang_mgr.get_string('ERROR.WRONG_PASSWORD'))
        else:
            password = base64.b64decode(metadata["password"]).decode()
            
        salt = f.read(32)
        iv = f.read(16)
        encrypted_data = f.read()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data

class PyZipEditor:
    def __init__(self):
        self.root = tkinterdnd2.Tk()
        self.root.title("PyZip编辑器")
        self.current_path = None
        self.temp_dir = None
        self.password = None
        self.current_dir = None
        self.root_dir = None
        self.clipboard = None
        self.clipboard_op = None  # 'cut' or 'copy'
        
        # 注册退出时的清理函数
        atexit.register(self.cleanup)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # 创建主界面
        self.create_gui()
        
    def cleanup(self):
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass
            self.temp_dir = None
            
    def on_closing(self):
        self.cleanup()
        self.root.destroy()

    def create_context_menu(self):
        # 空白处右键菜单
        self.blank_menu = tk.Menu(self.root, tearoff=0)
        self.blank_menu.add_command(label=lang_mgr.get_string('FILE.EXTRACT'), command=self.extract_all)
        self.blank_menu.add_command(label=lang_mgr.get_string('FILE.IMPORT'), command=self.import_files)
        self.blank_menu.add_command(label=lang_mgr.get_string('FILE.PASTE'), command=self.paste_files)
        
        # 添加新建子菜单
        self.new_menu = tk.Menu(self.blank_menu, tearoff=0)
        self.new_menu.add_command(label=lang_mgr.get_string('FILE.NEW_FILE'), command=self.new_file)
        self.new_menu.add_command(label=lang_mgr.get_string('FILE.NEW_FOLDER'), command=self.new_folder)
        self.blank_menu.add_cascade(label=lang_mgr.get_string('FILE.NEW'), menu=self.new_menu)

        # 文件右键菜单
        self.file_menu = tk.Menu(self.root, tearoff=0)
        self.file_menu.add_command(label=lang_mgr.get_string('FILE.OPEN'), command=self.open_selected)
        self.file_menu.add_command(label=lang_mgr.get_string('FILE.EXPORT'), command=self.export_selected)
        self.file_menu.add_separator()
        self.file_menu.add_command(label=lang_mgr.get_string('FILE.CUT'), command=self.cut_selected)
        self.file_menu.add_command(label=lang_mgr.get_string('FILE.COPY'), command=self.copy_selected)
        self.file_menu.add_command(label=lang_mgr.get_string('FILE.PASTE'), command=self.paste_files)
        self.file_menu.add_separator()
        self.file_menu.add_command(label=lang_mgr.get_string('FILE.DELETE'), command=self.delete_selected)
        self.file_menu.add_command(label=lang_mgr.get_string('FILE.RENAME'), command=self.rename_selected)
        
    def create_gui(self):
        # 创建菜单栏
        self.menubar = tk.Menu(self.root)
        self.root.config(menu=self.menubar)
        
        # 创建文件菜单
        self.file_menu_bar = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="file", menu=self.file_menu_bar)
        
        self.file_menu_bar.add_command(label=lang_mgr.get_string('FILE.NEW'), command=self.create_pyzip)
        self.file_menu_bar.add_command(label=lang_mgr.get_string('FILE.OPEN'), command=self.open_pyzip)
        self.file_menu_bar.add_command(label=lang_mgr.get_string('FILE.SAVE'), command=self.save_pyzip)
        self.file_menu_bar.add_command(label=lang_mgr.get_string('FILE.SAVE_AS'), command=self.saveas_pyzip)
        self.file_menu_bar.add_separator()
        self.file_menu_bar.add_command(label=lang_mgr.get_string('FILE.EXIT'), command=self.root.quit)

        # 创建设置菜单
        self.settings_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="settings", menu=self.settings_menu)
        
        # 语言子菜单
        self.lang_menu = tk.Menu(self.settings_menu, tearoff=0)
        self.settings_menu.add_cascade(label=lang_mgr.get_string('MENU.LANGUAGE'), menu=self.lang_menu)
        
        # 添加语言选项
        for lang_code in lang_mgr.available_langs.keys():
            self.lang_menu.add_command(
                label=lang_code,
                command=lambda code=lang_code: self.change_language(code)
            )

        # 创建预览框架
        preview_frame = tk.Frame(self.root)
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 创建工具栏
        toolbar = tk.Frame(preview_frame)
        toolbar.pack(fill=tk.X)
        
        self.back_btn = tk.Button(toolbar, text=lang_mgr.get_string('UI.BACK'), command=self.go_back, state=tk.DISABLED)
        self.back_btn.pack(side=tk.LEFT, padx=5)
        
        self.path_var = tk.StringVar()
        path_label = tk.Label(toolbar, textvariable=self.path_var)
        path_label.pack(side=tk.LEFT, padx=5)
        
        # 创建进度条
        self.progress_frame = tk.Frame(preview_frame)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var)
        self.progress_label = tk.Label(self.progress_frame, text="")
        
        # 创建文件列表
        self.tree = ttk.Treeview(preview_frame, columns=('name', 'size', 'modified'), show='headings')
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        self.tree.heading('name', text=lang_mgr.get_string('COLUMN.FILENAME'))
        self.tree.heading('size', text=lang_mgr.get_string('COLUMN.SIZE'))
        self.tree.heading('modified', text=lang_mgr.get_string('COLUMN.MODIFIED'))
        
        self.tree.bind('<Double-1>', self.on_double_click)
        self.tree.bind('<Button-3>', self.show_context_menu)
        self.tree.bind('<Button-1>', self.on_click)

        # 创建右键菜单
        self.create_context_menu()

        link = tk.Label(self.root, text="by:\nhttps://space.bilibili.com/3493120134088978?spm_id_from=333.337.0.0", fg="blue", cursor="hand2")
        link.pack(side=tk.BOTTOM, pady=10)
        link.bind("<Button-1>", lambda e: webbrowser.open("https://space.bilibili.com/3493120134088978?spm_id_from=333.337.0.0"))

    def on_click(self, event):
        # 获取点击位置的item
        item = self.tree.identify_row(event.y)
        if not item:
            # 如果点击空白处，清除选择
            self.tree.selection_remove(self.tree.selection())

    def cut_selected(self):
        selection = self.tree.selection()
        if selection:
            self.clipboard = selection[0]
            self.clipboard_op = 'cut'

    def copy_selected(self):
        selection = self.tree.selection()
        if selection:
            self.clipboard = selection[0]
            self.clipboard_op = 'copy'

    def paste_files(self):
        if not self.clipboard or not self.current_dir:
            return
            
        src_name = self.tree.item(self.clipboard)['text']
        src_path = os.path.join(self.current_dir, src_name)
        
        if not os.path.exists(src_path):
            return
            
        try:
            if os.path.isdir(src_path):
                if self.clipboard_op == 'cut':
                    shutil.move(src_path, self.current_dir)
                else:
                    shutil.copytree(src_path, os.path.join(self.current_dir, src_name))
            else:
                if self.clipboard_op == 'cut':
                    shutil.move(src_path, self.current_dir)
                else:
                    shutil.copy2(src_path, self.current_dir)
                    
            if self.clipboard_op == 'cut':
                self.clipboard = None
                self.clipboard_op = None
                
            self.refresh_file_list()
            
        except Exception as e:
            messagebox.showerror(
                lang_mgr.get_string('DIALOG.ERROR'),
                lang_mgr.get_string('ERROR.PASTE', str(e))
            )

    def change_language(self, lang_code):
        lang_mgr.set_language(lang_code)
        # 刷新界面文本
        self.refresh_ui_text()
        
    def refresh_ui_text(self):
        # 更新菜单文本
        self.blank_menu.entryconfig(0, label=lang_mgr.get_string('FILE.EXTRACT'))
        self.blank_menu.entryconfig(1, label=lang_mgr.get_string('FILE.IMPORT'))
        self.blank_menu.entryconfig(2, label=lang_mgr.get_string('FILE.PASTE'))
        
        self.new_menu.entryconfig(0, label=lang_mgr.get_string('FILE.NEW_FILE'))
        self.new_menu.entryconfig(1, label=lang_mgr.get_string('FILE.NEW_FOLDER'))
        
        self.file_menu.entryconfig(0, label=lang_mgr.get_string('FILE.OPEN'))
        self.file_menu.entryconfig(1, label=lang_mgr.get_string('FILE.EXPORT'))
        self.file_menu.entryconfig(3, label=lang_mgr.get_string('FILE.CUT'))
        self.file_menu.entryconfig(4, label=lang_mgr.get_string('FILE.COPY'))
        self.file_menu.entryconfig(5, label=lang_mgr.get_string('FILE.PASTE'))
        self.file_menu.entryconfig(7, label=lang_mgr.get_string('FILE.DELETE'))
        self.file_menu.entryconfig(8, label=lang_mgr.get_string('FILE.RENAME'))
        
        # 更新上栏菜单文本
        self.file_menu_bar.entryconfig(0, label=lang_mgr.get_string('FILE.NEW'))
        self.file_menu_bar.entryconfig(1, label=lang_mgr.get_string('FILE.OPEN'))
        self.file_menu_bar.entryconfig(2, label=lang_mgr.get_string('FILE.SAVE'))
        self.file_menu_bar.entryconfig(3, label=lang_mgr.get_string('FILE.SAVE_AS'))
        self.file_menu_bar.entryconfig(5, label=lang_mgr.get_string('FILE.EXIT'))
        
        self.settings_menu.entryconfig(0, label=lang_mgr.get_string('MENU.LANGUAGE'))
        
        # 更新按钮文本
        self.back_btn.config(text=lang_mgr.get_string('UI.BACK'))
        
        # 更新表头
        self.tree.heading('name', text=lang_mgr.get_string('COLUMN.FILENAME'))
        self.tree.heading('size', text=lang_mgr.get_string('COLUMN.SIZE'))
        self.tree.heading('modified', text=lang_mgr.get_string('COLUMN.MODIFIED'))

    def new_file(self):
        if not self.current_dir:
            return
        filename = tk.simpledialog.askstring(
            title=lang_mgr.get_string('FILE.NEW_FILE'),
            prompt=lang_mgr.get_string('DIALOG.ENTER_FILENAME')
        )
        if filename:
            try:
                filepath = os.path.join(self.current_dir, filename)
                with open(filepath, 'w') as f:
                    pass
                self.refresh_file_list()
            except Exception as e:
                messagebox.showerror(
                    lang_mgr.get_string('DIALOG.ERROR'),
                    lang_mgr.get_string('ERROR.CREATE_FILE', str(e))
                )

    def new_folder(self):
        if not self.current_dir:
            return
        foldername = tk.simpledialog.askstring(
            title=lang_mgr.get_string('FILE.NEW_FOLDER'),
            prompt=lang_mgr.get_string('DIALOG.ENTER_FOLDERNAME')
        )
        if foldername:
            try:
                folderpath = os.path.join(self.current_dir, foldername)
                os.makedirs(folderpath)
                self.refresh_file_list()
            except Exception as e:
                messagebox.showerror(
                    lang_mgr.get_string('DIALOG.ERROR'),
                    lang_mgr.get_string('ERROR.CREATE_FOLDER', str(e))
                )

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            # 选中并显示文件菜单
            self.tree.selection_set(item)
            self.file_menu.post(event.x_root, event.y_root)
        else:
            # 显示空白处菜单
            self.blank_menu.post(event.x_root, event.y_root)

    def extract_all(self):
        if not self.current_dir:
            return
        target_dir = askdirectory(title=lang_mgr.get_string('UI.SELECT_EXTRACT_DIR'))
        if target_dir:
            try:
                shutil.copytree(self.current_dir, target_dir, dirs_exist_ok=True)
                messagebox.showinfo(
                    lang_mgr.get_string('DIALOG.SUCCESS'),
                    lang_mgr.get_string('DIALOG.EXTRACT_SUCCESS')
                )
            except Exception as e:
                messagebox.showerror(
                    lang_mgr.get_string('DIALOG.ERROR'),
                    lang_mgr.get_string('ERROR.EXTRACT', str(e))
                )

    def import_files(self):
        if not self.current_dir:
            return
        files = askopenfilename(multiple=True)
        if files:
            for file in files:
                try:
                    shutil.copy2(file, self.current_dir)
                except Exception as e:
                    messagebox.showerror(
                        lang_mgr.get_string('DIALOG.ERROR'),
                        lang_mgr.get_string('ERROR.IMPORT', file, str(e))
                    )
            self.refresh_file_list()

    def open_selected(self):
        selection = self.tree.selection()
        if selection:
            self.on_double_click(None)

    def export_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        item = selection[0]
        filename = self.tree.item(item)['text']
        source_path = os.path.join(self.current_dir, filename)
        
        if os.path.isdir(source_path):
            target_dir = askdirectory(title=lang_mgr.get_string('UI.SELECT_EXPORT_DIR'))
            if target_dir:
                target_path = os.path.join(target_dir, filename)
                try:
                    shutil.copytree(source_path, target_path)
                    messagebox.showinfo(
                        lang_mgr.get_string('DIALOG.SUCCESS'),
                        lang_mgr.get_string('DIALOG.EXPORT_SUCCESS')
                    )
                except Exception as e:
                    messagebox.showerror(
                        lang_mgr.get_string('DIALOG.ERROR'),
                        lang_mgr.get_string('ERROR.EXPORT', str(e))
                    )
        else:
            target_file = asksaveasfilename(
                initialfile=filename,
                title=lang_mgr.get_string('UI.SELECT_EXPORT_FILE')
            )
            if target_file:
                try:
                    shutil.copy2(source_path, target_file)
                    messagebox.showinfo(
                        lang_mgr.get_string('DIALOG.SUCCESS'),
                        lang_mgr.get_string('DIALOG.EXPORT_SUCCESS')
                    )
                except Exception as e:
                    messagebox.showerror(
                        lang_mgr.get_string('DIALOG.ERROR'),
                        lang_mgr.get_string('ERROR.EXPORT', str(e))
                    )

    def delete_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        item = selection[0]
        filename = self.tree.item(item)['text']
        if messagebox.askyesno(
            lang_mgr.get_string('DIALOG.CONFIRM_DELETE'),
            lang_mgr.get_string('DIALOG.CONFIRM_DELETE', filename)
        ):
            try:
                path = os.path.join(self.current_dir, filename)
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                self.refresh_file_list()
            except Exception as e:
                messagebox.showerror(
                    lang_mgr.get_string('DIALOG.ERROR'),
                    lang_mgr.get_string('ERROR.DELETE', str(e))
                )

    def rename_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        item = selection[0]
        old_name = self.tree.item(item)['text']
        new_name = tk.simpledialog.askstring(
            title=lang_mgr.get_string('DIALOG.RENAME'),
            prompt=lang_mgr.get_string('DIALOG.ENTER_NEW_NAME')
        )
        if new_name:
            try:
                old_path = os.path.join(self.current_dir, old_name)
                new_path = os.path.join(self.current_dir, new_name)
                os.rename(old_path, new_path)
                self.refresh_file_list()
            except Exception as e:
                messagebox.showerror(
                    lang_mgr.get_string('DIALOG.ERROR'),
                    lang_mgr.get_string('ERROR.RENAME', str(e))
                )

    def show_progress(self, show=True):
        if show:
            self.progress_frame.pack(fill=tk.X, pady=5)
            self.progress_bar.pack(fill=tk.X)
            self.progress_label.pack()
        else:
            self.progress_frame.pack_forget()

    def update_progress(self, value, text):
        # 使用after_idle代替直接更新,避免递归调用
        self.root.after_idle(lambda: [
            self.progress_var.set(value),
            self.progress_label.configure(text=text)
        ])

    def refresh_file_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        if not self.current_dir:
            return
            
        try:
            items = os.listdir(self.current_dir)
            for item in items:
                full_path = os.path.join(self.current_dir, item)
                size, modified = get_file_info(full_path)
                icon = get_file_icon(full_path)
                self.tree.insert('', 'end', text=item, values=(f"{icon} {item}", size, modified))
        except Exception as e:
            messagebox.showerror(
                lang_mgr.get_string('DIALOG.ERROR'),
                lang_mgr.get_string('ERROR.READ_DIR', str(e))
            )

    def on_double_click(self, event):
        try:
            item = self.tree.selection()[0]
            item_text = self.tree.item(item)['text']
            full_path = os.path.join(self.current_dir, item_text)
            
            if os.path.isdir(full_path):
                self.current_dir = full_path
                rel_path = os.path.relpath(self.current_dir, self.root_dir)
                self.path_var.set(f"/{rel_path}")
                self.back_btn.configure(state=tk.NORMAL)
                self.refresh_file_list()
            else:
                os.startfile(long_path(full_path))
        except IndexError:
            pass

    def go_back(self):
        if self.current_dir and self.current_dir != self.root_dir:
            parent = os.path.dirname(self.current_dir)
            self.current_dir = parent
            if parent == self.root_dir:
                self.path_var.set("/")
                self.back_btn.configure(state=tk.DISABLED)
            else:
                rel_path = os.path.relpath(parent, self.root_dir)
                self.path_var.set(f"/{rel_path}")
            self.refresh_file_list()

    def save_pyzip(self):
        if not self.current_path or not self.current_dir:
            self.saveas_pyzip()
            return
            
        def save_task():
            try:
                temp_zip = tempfile.mktemp(suffix='.zip')
                
                # 计算总文件数
                total_files = sum([len(files) for _, _, files in os.walk(self.current_dir)])
                processed_files = 0
                
                self.show_progress(True)
                
                with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for root, _, files in os.walk(self.current_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, self.current_dir)
                            zf.write(file_path, arcname)
                            processed_files += 1
                            progress = (processed_files / total_files) * 100
                            self.root.after_idle(lambda p=progress, f=file: self.update_progress(p, lang_mgr.get_string('UI.COMPRESSING', f)))
                
                with open(temp_zip, 'rb') as f:
                    zip_data = f.read()
                    
                with open(self.current_path, 'wb') as f:
                    f.write(zip_data)
                    
                self.update_progress(100, lang_mgr.get_string('UI.ENCRYPTING'))
                encrypt_file(self.current_path, self.password)
                
                os.remove(temp_zip)
                
                self.root.after_idle(lambda: [
                    self.show_progress(False),
                    messagebox.showinfo(
                        lang_mgr.get_string('DIALOG.SUCCESS'),
                        lang_mgr.get_string('DIALOG.FILE_SAVED')
                    )
                ])
                
            except Exception as e:
                messagebox.showerror(
                    lang_mgr.get_string('DIALOG.ERROR'),
                    lang_mgr.get_string('ERROR.SAVE', str(e))
                )
                self.root.after_idle(lambda: self.show_progress(False))
        
        threading.Thread(target=save_task, daemon=True).start()

    def saveas_pyzip(self):
        if not self.current_dir:
            messagebox.showerror(
                lang_mgr.get_string('DIALOG.ERROR'),
                lang_mgr.get_string('ERROR.NO_CONTENT')
            )
            return
            
        file_path = asksaveasfilename(
            defaultextension=".pyzip",
            filetypes=[("PyZip files", "*.pyzip")]
        )
        if not file_path:
            return
            
        self.current_path = file_path
        if not self.password:
            chars = string.ascii_letters + string.digits + string.punctuation
            self.password = ''.join(secrets.choice(chars) for _ in range(32))
            
        self.save_pyzip()

    def create_pyzip(self):
        folder_path = askdirectory(title=lang_mgr.get_string('UI.SELECT_COMPRESS_DIR'))
        if not folder_path:
            return
            
        file_path = asksaveasfilename(
            defaultextension=".pyzip",
            filetypes=[("PyZip files", "*.pyzip")]
        )
        if not file_path:
            return
            
        self.current_path = file_path
        chars = string.ascii_letters + string.digits + string.punctuation
        self.password = ''.join(secrets.choice(chars) for _ in range(32))
        
        def compress_task():
            try:
                temp_zip = tempfile.mktemp(suffix='.zip')
                
                # 计算总文件数
                total_files = sum([len(files) for _, _, files in os.walk(folder_path)])
                processed_files = 0
                
                self.show_progress(True)
                
                with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for root, _, files in os.walk(folder_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, folder_path)
                            zf.write(file_path, arcname)
                            processed_files += 1
                            progress = (processed_files / total_files) * 100
                            self.root.after_idle(lambda p=progress, f=file: self.update_progress(p, lang_mgr.get_string('UI.COMPRESSING', f)))
                
                with open(temp_zip, 'rb') as f:
                    zip_data = f.read()
                    
                with open(self.current_path, 'wb') as f:
                    f.write(zip_data)
                    
                self.update_progress(100, lang_mgr.get_string('UI.ENCRYPTING'))
                encrypt_file(self.current_path, self.password)
                
                os.remove(temp_zip)
                
                self.root.after_idle(lambda: [
                    self.show_progress(False),
                    messagebox.showinfo(
                        lang_mgr.get_string('DIALOG.SUCCESS'),
                        lang_mgr.get_string('DIALOG.NEW_PYZIP_CREATED')
                    )
                ])
                
            except Exception as e:
                messagebox.showerror(
                    lang_mgr.get_string('DIALOG.ERROR'),
                    lang_mgr.get_string('ERROR.CREATE_FILE', str(e))
                )
                self.current_path = None
                self.password = None
                self.root.after_idle(lambda: self.show_progress(False))
        
        threading.Thread(target=compress_task, daemon=True).start()

    def open_pyzip(self):
        file_path = askopenfilename(
            defaultextension=".pyzip",
            filetypes=[("PyZip files", "*.pyzip")]
        )
        if file_path:
            self.current_path = file_path
            
            def extract_task():
                try:
                    self.temp_dir = tempfile.mkdtemp()
                    temp_zip = os.path.join(self.temp_dir, "temp.zip")
                    
                    self.show_progress(True)
                    self.update_progress(0, lang_mgr.get_string('UI.DECRYPTING'))
                    
                    decrypted_data = decrypt_file(file_path)
                    
                    with open(temp_zip, 'wb') as f:
                        f.write(decrypted_data)
                    
                    self.update_progress(50, lang_mgr.get_string('UI.EXTRACTING'))
                    
                    with zipfile.ZipFile(temp_zip, 'r') as zf:
                        total_files = len(zf.namelist())
                        for i, member in enumerate(zf.namelist(), 1):
                            zf.extract(member, self.temp_dir)
                            progress = 50 + (i / total_files) * 50
                            self.root.after_idle(lambda p=progress, m=member: self.update_progress(p, lang_mgr.get_string('UI.EXTRACTING', m)))
                    
                    os.remove(temp_zip)
                    self.current_dir = self.temp_dir
                    self.root_dir = self.temp_dir
                    self.root.after_idle(lambda: [
                        self.path_var.set("/"),
                        self.back_btn.config(state=tk.DISABLED),
                        self.refresh_file_list(),
                        self.show_progress(False)
                    ])
                    
                except Exception as e:
                    messagebox.showerror(
                        lang_mgr.get_string('DIALOG.ERROR'),
                        lang_mgr.get_string('ERROR.OPEN_FILE', str(e))
                    )
                    self.current_path = None
                    self.password = None
                    self.root.after_idle(lambda: self.show_progress(False))
            
            threading.Thread(target=extract_task, daemon=True).start()

    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    editor = PyZipEditor()
    editor.run()
