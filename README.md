# Edge-AI-Based-Faster-USB-Intrusion-Detector
This project presents a lightweight yet powerful Edge AI-based USB Intrusion Detection and Protection System, designed to secure computers from USB-borne threats — including malware, suspicious executables, and anomalous file behavior.

Unlike traditional antivirus solutions, this system operates offline, using machine learning and behavior analysis to identify and block malicious USB devices in real-time. It combines both signature-based (static file features) and behavior-based (USB usage patterns) scanning for comprehensive protection.

**Technologies & Libraries Used:**
1. Python – Core implementation language
2. ONNX & ONNXRuntime – For optimized edge inference of AI models
3. psutil – System monitoring (detecting USBs, processes, IO stats)
4. pandas, numpy – Data handling and preprocessing
5. math – Shannon entropy calculation
6. Tkinter – GUI for user interaction
7. threading – Smooth background operations during GUI runtime
8. os, time – File operations and system commands (e.g., unmounting)

**Status:**
1. Signature-based model implemented
2. Behavior-based model integrated
3. GUI and detection system complete
4. Edge AI ONNX inference working offline
5. Future: Logging USB scan history, multi-USB scanning, performance optimization


Developed by "Team EdgeSec" - **Priyanshu Jugran** (Team Lead)
