# -*- coding:utf-8 -*-
import os
import datetime
import tkinter as tk  # tkinter 是 Python 的标准库之一，适用于创建简单的 GUI 应用程序
from tkinter import filedialog, ttk  # 导入ttk模块
import threading  # 用于多线程处理
from tkinter.scrolledtext import ScrolledText

# 文件头映射
FILE_HEADERS = {
    1: (0x89, 0x50, 0x4e),  # PNG 文件头
    2: (0x47, 0x49, 0x46),  # GIF 文件头
    3: (0xff, 0xd8, 0xff),  # JPG 文件头
    4: (0x42, 0x4d),  # BMP 文件头
    5: (0x49, 0x49, 0x2a, 0x00),  # TIFF 小端字节序
    6: (0x4d, 0x4d, 0x00, 0x2a),  # TIFF 大端字节序
    7: (0x52, 0x49, 0x46, 0x46),  # WEBP 文件头
    8: (0x66, 0x74, 0x79, 0x70),  # HEIF 文件头
    9: (0x00, 0x00, 0x01, 0x00),  # ICO 文件头
    10: (0x3c, 0x3f, 0x78, 0x6d),  # SVG 文件头
}
# 后缀映射
extensions = {
    1: '.png',  # PNG
    2: '.gif',  # GIF
    3: '.jpg',  # JPG
    4: '.bmp',  # BMP
    5: '.tiff',  # TIFF
    6: '.webp',  # WEBP
    7: '.heif',  # HEIF
    8: '.ico',  # ICO
    9: '.svg',  # SVG
}


class DirectorySelectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("选择文件夹")

        # 日志路径（初始化为空）
        self.log_path = ""

        # 递归存储选项
        self.recursive_option = tk.StringVar(value="recursive")  # 默认递归存储

        # 创建控件和标签
        self.create_widgets()

    def create_widgets(self):
        # 输入目录
        self.input_label = tk.Label(self.root, text="选择输入目录（.dat 文件所在目录）:")
        self.input_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")

        self.input_button = tk.Button(self.root, text="选择输入目录", command=self.select_input_directory)
        self.input_button.grid(row=0, column=1, padx=10, pady=10)

        self.input_path_var = tk.StringVar()
        self.input_path_entry = tk.Entry(self.root, textvariable=self.input_path_var, width=40)
        self.input_path_entry.grid(row=0, column=2, padx=10, pady=10)

        # 输出目录
        self.output_label = tk.Label(self.root, text="选择输出目录（图片存放目录）:")
        self.output_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")

        self.output_button = tk.Button(self.root, text="选择输出目录", command=self.select_output_directory)
        self.output_button.grid(row=1, column=1, padx=10, pady=10)

        self.output_path_var = tk.StringVar()
        self.output_path_entry = tk.Entry(self.root, textvariable=self.output_path_var, width=40)
        self.output_path_entry.grid(row=1, column=2, padx=10, pady=10)

        # 错误日志目录
        self.log_label = tk.Label(self.root, text="选择错误日志文件存放目录:")
        self.log_label.grid(row=2, column=0, padx=10, pady=10, sticky="e")

        self.log_button = tk.Button(self.root, text="选择日志目录", command=self.select_log_directory)
        self.log_button.grid(row=2, column=1, padx=10, pady=10)

        self.log_path_var = tk.StringVar()
        self.log_path_entry = tk.Entry(self.root, textvariable=self.log_path_var, width=40)
        self.log_path_entry.grid(row=2, column=2, padx=10, pady=10)

        # 存储选项
        self.option_label = tk.Label(self.root, text="选择存储方式:")
        self.option_label.grid(row=3, column=0, padx=10, pady=10, sticky="e")

        self.recursive_radio = tk.Radiobutton(self.root, text="递归存储", variable=self.recursive_option,
                                              value="recursive")
        self.recursive_radio.grid(row=3, column=1, padx=10, pady=10)

        self.non_recursive_radio = tk.Radiobutton(self.root, text="非递归存储", variable=self.recursive_option,
                                                  value="non_recursive")
        self.non_recursive_radio.grid(row=3, column=2, padx=10, pady=10)

        # 开始处理按钮
        self.start_button = tk.Button(self.root, text="开始处理", command=self.start_processing)
        self.start_button.grid(row=4, column=0, columnspan=3, padx=10, pady=20)

        # 进度条
        self.progress_label = tk.Label(self.root, text="进度: 0%")
        self.progress_label.grid(row=5, column=0, columnspan=3, padx=10, pady=10)

        # 错误信息显示
        self.error_label = tk.Label(self.root, text="", fg="red")
        self.error_label.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

        # 初始化进度条
        self.progress_bar = ttk.Progressbar(self.root, orient="horizontal", length=400, mode="determinate")
        self.progress_bar.grid(row=5, column=0, columnspan=3, padx=10, pady=10)

        # 消息日志框
        self.message_log = ScrolledText(self.root, width=60, height=10, state="disabled", wrap="word")
        self.message_log.grid(row=7, column=0, columnspan=3, padx=10, pady=10)

    def select_input_directory(self):
        folder_selected = filedialog.askdirectory(title="选择输入目录（.dat 文件所在目录）")
        self.input_path_var.set(folder_selected)

    def select_output_directory(self):
        folder_selected = filedialog.askdirectory(title="选择输出目录（图片存放目录）")
        self.output_path_var.set(folder_selected)

    def select_log_directory(self):
        folder_selected = filedialog.askdirectory(title="选择错误日志文件存放目录")
        if folder_selected:
            self.log_path_var.set(folder_selected)
            self.log_path = folder_selected  # 保存日志路径,将日志路径保存为类的一个属性
            os.makedirs(folder_selected, exist_ok=True)  # 确保目录存在

    def start_processing(self):
        # 获取目录路径
        into_path = self.input_path_var.get()
        out_path = self.output_path_var.get()
        log_path = self.log_path_var.get()
        storage_mode = self.recursive_option.get()  # 获取用户选择的存储方式

        # 验证输入目录、输出目录和日志目录是否已选择
        if not all([into_path, out_path, log_path]):
            self.show_error("请确保所有目录已选择!")
            return

        # 禁用开始处理按钮
        self.start_button.config(state=tk.DISABLED)

        # 使用线程来避免阻塞界面
        processing_thread = threading.Thread(target=self.process_files,
                                             args=(into_path, out_path, storage_mode))
        processing_thread.start()

    def process_files(self, into_path, out_path, storage_mode):
        try:
            dat_list = dat_files(into_path)
            lens = len(dat_list)

            if lens == 0:
                self.show_error("没有找到dat文件")
                return
            # 初始化进度条
            self.update_progress(0, lens)

            # 使用 tqdm 显示进度条
            for i, dat_file in enumerate(dat_list):
                dat_file_name = os.path.splitext(os.path.basename(dat_file))[0]

                # 根据存储方式调整目标路径
                if storage_mode == "recursive":
                    relative_path = os.path.relpath(dat_file, into_path)
                    target_subdir = os.path.join(out_path, os.path.dirname(relative_path))
                else:
                    target_subdir = out_path

                target_subdir = os.path.abspath(target_subdir)
                os.makedirs(target_subdir, exist_ok=True)

                try:
                    image_decode(dat_file, dat_file_name, target_subdir, self.log_error)
                except Exception as e:
                    self.log_error(dat_file, f"文件处理失败: {str(e)}")

                # 实时更新进度条
                self.update_progress((i + 1), lens)

            self.root.after(0, self.show_success, "所有文件已处理完成！")
        except Exception as e:
            self.show_error(f"处理过程中发生错误: {str(e)}")
        finally:
            self.start_button.config(state=tk.NORMAL)

    def update_progress(self, current, total):
        if total <= 0:  # 避免除零错误
            self.progress_bar["value"] = 0
            self.progress_label.config(text="进度: 0%")
            return
        # 计算百分比并限制范围
        percentage = max(0, min(100, int((current / total) * 100)))
        self.progress_bar["value"] = percentage
        self.progress_label.config(text=f"进度: {percentage}%")

    def log_message(self, message, is_error=False):
        """
        在滚动文本框中记录消息
        :param message: 要记录的消息文本
        :param is_error: 是否是错误消息
        """
        self.message_log.config(state="normal")  # 允许修改
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color = "red" if is_error else "green"
        formatted_message = f"[{timestamp}] {message}\n"

        self.message_log.insert("end", formatted_message, color)
        self.message_log.tag_config(color, foreground=color)
        self.message_log.config(state="disabled")  # 禁止修改
        self.message_log.see("end")  # 滚动到底部

    def show_error(self, message):
        """
        显示错误信息并记录到日志框
        """
        self.error_label.config(text=message)
        self.log_message(message, is_error=True)

    def show_success(self, message):
        """
        显示错误信息并记录到日志框
        """
        self.error_label.config(text=message)
        self.log_message(message, is_error=True)
        # self.error_label.config(text="", fg="green")
        # self.progress_label.config(text=message)

    def log_error(self, file_name, error_message):
        """
        将错误记录到日志文件
        """
        if not self.log_path:
            self.show_error("日志路径未设置")
            return

        try:
            # 确保日志文件路径有效
            date_str = datetime.datetime.now().strftime("%Y-%m-%d")
            log_name = f"error_log_{date_str}.txt"
            file_log_path = os.path.join(self.log_path, log_name)
            with open(file_log_path, "a", encoding="utf-8") as log_file:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_file.write(f"[{timestamp}] 文件: {file_name} 错误: {error_message}\n")
        except Exception as e:
            self.show_error(f"记录错误日志失败: {str(e)}")


def select_directory(title):
    """
    弹出文件夹选择对话框，返回选择的目录路径
    """
    return filedialog.askdirectory(title=title)


def dat_files(file_dir):
    """
    递归获取所有 .dat 文件
    """
    dat_files_list = []
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            if file.endswith('.dat'):
                dat_files_list.append(os.path.join(root, file))  # 返回绝对路径
    return dat_files_list


def image_decode(temp_path, dat_file_name, out_path, log_error_callback):
    """
    解码 .dat 文件并转换为图片
    """
    if not os.path.isdir(out_path):
        log_error_callback(temp_path, "无效的输出目录")
        raise ValueError(f"无效的输出目录: {out_path}")
    try:
        xo, fmt_index = detect_format(temp_path, log_error_callback)
    except Exception as e:
        log_error_callback(temp_path, f"格式检测失败: {str(e)}")
        raise
    # 确保输出目录存在
    os.makedirs(out_path, exist_ok=True)
    # 文件格式映射表
    mat = extensions.get(fmt_index, '.jpg')  # 默认格式为 JPG
    # 构造输出文件路径
    out_file = os.path.join(out_path, dat_file_name + mat)

    try:
        # 写入解码后的图片
        with open(temp_path, "rb") as dat_read, open(out_file, "wb") as png_write:
            while chunk := dat_read.read(8192):
                decoded_chunk = bytes([byte ^ xo for byte in chunk])
                png_write.write(decoded_chunk)
    except Exception as e:
        if os.path.exists(out_file):
            os.remove(out_file)  # 删除未完整写入的文件
        log_error_callback(temp_path, f"解码失败: {str(e)}")
        raise


def detect_format(f, log_error_callback):
    """
    检测文件格式及解码参数
    """
    if not callable(log_error_callback):
        raise ValueError("log_error_callback 必须是一个可调用对象")

    try:
        with open(f, "rb") as dat_r:
            now = dat_r.read(max(len(header) for header in FILE_HEADERS.values()))  # 读取最长的文件头
            for ext, header in FILE_HEADERS.items():
                if len(now) >= len(header):  # 确保读取的字节数足够
                    res = [now[i] ^ header[i] for i in range(len(header))]
                    if all(x == res[0] for x in res):  # 检查是否一致
                        return res[0], ext
    except Exception as e:
        log_error_callback(f, f"格式检测出错: {str(e)}")
    return 0, ".unknown"  # 无法检测到格式时返回默认值


if __name__ == '__main__':
    root = tk.Tk()
    app = DirectorySelectionApp(root)
    root.mainloop()
