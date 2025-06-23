import psutil
import time
import os
import math
import pandas as pd
import joblib

usb_path = None
usb_input_ds = None
malicious = None

#func to get list of removable drives
def get_usb_drive_list():
    drives = []

    for d in psutil.disk_partitions(all = False):
        if('removable' in d.opts):
            drives.append(d.device)
    
    return drives



#func for usb detection
def detect_usb():
    global usb_path
    print("Watching for usb inserions...")

    prev_usb_list = get_usb_drive_list()

    while True:
        time.sleep(2)

        curr_usb_list = get_usb_drive_list()

        new_usb = []
        for usb in curr_usb_list:
            if(usb not in prev_usb_list):
                new_usb.append(usb)
        
        if new_usb:
            for usb in new_usb:
                print(f"USB detected: {usb}")
                usb_path = usb
                extract_features(usb_path)
                unmount_usb(usb_path[:2])
                predict_usb()
                return      
            
#func to calc entropy
def get_entropy(file_path):
    try:
        with open(file_path, 'rb')as f:
            byte_arr = f.read()
        
        if len(byte_arr)==0:
            return 0
        
        freq = {}
        for byte in byte_arr:
            freq[byte] = freq.get(byte,0)+1
        
        entropy = 0
        for count in freq.values():
            p = count / len(byte_arr)
            entropy -= p*math.log2(p)
        
        return entropy
    
    except:
        return 0


#func to extract features
def extract_features(usb_path):
    global usb_input_ds
    suspicious_exts = ['.exe', '.dll', '.scr', '.bat', '.vbs', '.js', '.cmd', '.ps1', '.jar', '.apk', '.com', '.pyd', '.ax', '.mui']

    data = []
    print("Extracting features...")
    for root,dirs,files in os.walk(usb_path):
        for file in files:
            try:
                file_path = os.path.join(root,file)
                size = os.path.getsize(file_path)/1024
                _,ext = os.path.splitext(file)
                ext = ext.lower() if ext else '.none'
                ext_flag = 1 if ext in suspicious_exts else 0
                entropy = get_entropy(file_path)
                data.append([round(size,2),ext_flag,entropy])

            except Exception as e:
                print(f"Error reading file: {file} : {e}")
    
    usb_input_ds = pd.DataFrame(data, columns=['filesize','extflag','entropy'])
    print("Features extracted successfully")


#func to unmount usb
def unmount_usb(usb_drive):
    try:
        print(f"Unmounting USB drive : {usb_drive}")
        os.system(f"mountvol {usb_drive} /p") 
        print("USB unmounted successfully...")
    except Exception as e:
        print(f"Error unmounting USB: {e}")


#func to predict usb
def predict_usb():
    global usb_input_ds
    global malicious

    model = joblib.load('bestAIModel.joblib')
    if usb_input_ds is None or usb_input_ds.empty:
        print("No data to predict")
        return
    
    X = usb_input_ds[['filesize', 'extflag', 'entropy']]
    pred = model.predict(X)

    if any(pred == 1):
        print("Warning! USB is Malicious : Please remove it asap")
        malicious = True
    else:
        malicious = False
        print("USB is safe : Please re-insert it")


#main    
def main():
    detect_usb()
    
main()