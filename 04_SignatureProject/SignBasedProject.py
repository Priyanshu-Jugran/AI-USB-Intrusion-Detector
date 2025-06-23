#____________________________library used__________________________________________________________________________
import os
import time
import math
import psutil
import threading
import pandas as pd
import joblib
from tkinter import *
from tkinter import messagebox

#____________________ global variable declaration___________________________________________________________________________________________
usb_path = None
usb_input_ds = None
malicious = None

#list of suspicious extensions for flagging purpose
suspicious_exts = ['.exe', '.dll', '.scr', '.bat', '.vbs', '.js', '.cmd', '.ps1', '.jar', '.apk', '.com', '.pyd', '.ax', '.mui']

#__________________________gui setup______________________________________________________________________________________________________________
root = Tk()
root.title("AUIDPS")
root.geometry("500x300") 

def update_status(msg):
    status_label.config(text=f"Status: {msg}")
    root.update_idletasks()

def on_block_pressed():
    messagebox.showinfo("USB Blocked", "USB blocked. Please remove it.")
    root.quit()
    
def on_ignore_pressed():
    messagebox.showinfo("USB Unmounted", "USB Unmounted due to security issue...\nPlease re-insert it.")
    root.quit()

def on_usb_detected():
    status_label.config(text=f"Status : USB detected in drive - {usb_path}", fg="green")
    scan_button.pack(pady=10)

label_font = ("Arial", 14, "bold")
button_font = ("Arial", 12)
button_style = {"font": button_font, "bd": 2, "relief": "ridge", "bg": "light grey", "activebackground": "dark grey"}


status_label = Label(root, text="Status : Checking for USB insertion...", font=label_font, fg="black")
status_label.pack(pady=30)

result_label = Label(root, text="", font=("Arial", 18), fg="black")
result_label.pack(pady=10)

scan_button = Button(root, text="Scan USB", command=lambda: threading.Thread(target=scan_usb).start(), **button_style)
malware_buttons_frame = Frame(root, bg="light grey")
block_button = Button(malware_buttons_frame, text="Block\n(Recommended)", command=on_block_pressed, **button_style)
continue_malware_button = Button(malware_buttons_frame, text="Ignore\n(Not Recommended)", command=on_ignore_pressed, **button_style)
continue_clean_button = Button(root, text="Finish", command=root.quit, **button_style)

#___________________________functions________________________________________________________________________________________________________

#func to get list of removable drives
def get_usb_drive_list():
    drives = []
    for d in psutil.disk_partitions(all=False):
        if 'removable' in d.opts:
            drives.append(d.device)
    return drives

#func to detect usb insertion
def detect_usb():
    global usb_path
    prev_usb_list = get_usb_drive_list()
    while True:
        time.sleep(1)
        curr_usb_list = get_usb_drive_list()
        new_usb = [usb for usb in curr_usb_list if usb not in prev_usb_list]
        if new_usb:
            usb_path = new_usb[0]
            root.after(0, on_usb_detected)
            return
        prev_usb_list = curr_usb_list


#func to calculate entropy using shannon formula
def get_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            byte_arr = f.read()
        if len(byte_arr) == 0:
            return 0
        freq = {}
        for byte in byte_arr:
            freq[byte] = freq.get(byte, 0) + 1
        entropy = -sum((count / len(byte_arr)) * math.log2(count / len(byte_arr)) for count in freq.values())
        return entropy
    except:
        return 0

#func to extract features
def extract_features(path):
    global usb_input_ds
    update_status("Extracting Features...")
    data = []
    for root_dir, dirs, files in os.walk(path):
        for file in files:
            try:
                file_path = os.path.join(root_dir, file)
                size = os.path.getsize(file_path) / 1024
                _, ext = os.path.splitext(file)
                ext = ext.lower() if ext else '.none'
                ext_flag = 1 if ext in suspicious_exts else 0
                entropy = get_entropy(file_path)
                data.append([round(size, 2), ext_flag, entropy])
            except Exception as e:
                print(f"Error reading {file}: {e}")
    usb_input_ds = pd.DataFrame(data, columns=['filesize', 'extflag', 'entropy'])
    update_status("Feature extraction done")
    print("Features extracted.")

#func to unmount usb
def unmount_usb(drive_letter):
    try:
        print(f"Unmounting {drive_letter}")
        os.system(f"mountvol {drive_letter} /p")
        print("USB unmounted.")
    except Exception as e:
        print(f"Unmount failed: {e}")

#func to get ai predictions
def predict_usb():
    global malicious
    update_status("Running prediction...")
    model = joblib.load('bestAIModel.joblib')
    if usb_input_ds is None or usb_input_ds.empty:
        print("No data to predict")
        return False
    X = usb_input_ds[['filesize', 'extflag', 'entropy']]
    pred = model.predict(X)
    malicious = any(pred == 1)
    update_status("Scan completed.")
    return malicious

#func for scanning usb
def scan_usb():
    status_label.config(text="Status : Extracting Features...", fg="blue")
    scan_button.pack_forget()
    extract_features(usb_path)
    unmount_usb(usb_path[:2])
    result = predict_usb()
    root.after(1000, lambda: show_scan_result(result))

def show_scan_result(found_malware):
    status_label.config(text="Status : Scan completed")
    if found_malware:
        result_label.config(text="⚠️ Malware detected in USB!", fg="red")
        show_malware_buttons()
    else:
        result_label.config(text="✅ No malware found. USB is clean.", fg="green")
        continue_clean_button.pack(pady=10)

def show_malware_buttons():
    malware_buttons_frame.pack(pady=10)
    block_button.pack(side=LEFT, padx=5)
    continue_malware_button.pack(side=LEFT, padx=5)


#start usb detecting thread & start gui loop
threading.Thread(target=detect_usb).start()
root.mainloop()

#_________________________end of project______________________________________________________________________________