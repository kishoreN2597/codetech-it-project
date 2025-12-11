File Integrity Monitoring (FIM) – Python GUI Tool

Author: KISHORE N
College: PSNA COLLEGE OF ENGINEERING AND TECHNOLOGY
Internship ID: CT04DR3196
Internship Provider: CODTECH IT SOLUTIONS PVT. LTD.

📌 Project Overview

This project implements a File Integrity Monitoring (FIM) tool using Python, Tkinter, hashlib, and Watchdog.
The tool calculates cryptographic hashes (SHA-256, SHA1, MD5) to detect:

NEW Files

MODIFIED Files

DELETED Files

UNCHANGED Files

The system includes:

✔ GUI Dashboard
✔ Real-time File Monitoring
✔ Accept Change System
✔ Screenshot Evidence
✔ Full Internship Report (PDF)

📂 Project Files
File	Description
fim_gui.py	Main Python GUI Application
hash_database_public.json	Sanitized hash database
hai.txt	Sample monitored file
screenshots/	GUI & file screenshots
Final_FIM_Report_KISHORE.pdf	Internship project report
📦 Installation
1. Install Requirements
pip install watchdog

2. Run Application
python3 fim_gui.py

⚙️ Features
✔ Initial Baseline Hashing

Creates a JSON database of cryptographic file hashes.

✔ One-Shot Integrity Verification

Compares existing file hashes with the stored baseline.

✔ Real-Time Monitoring

Uses Watchdog to detect changes instantly.

✔ Accept Changes

Updates the baseline after verification.

✔ Multiple Hash Algorithms

SHA256

SHA1

MD5

📸 Screenshots

Screenshots are available in the /screenshots/ folder.

📑 Final Internship Report

Full report located:
Final_FIM_Report_KISHORE.pdf

📜 License

This project is released under the MIT License.

🙌 Acknowledgements

Special thanks to CODTECH IT SOLUTIONS PVT. LTD. for providing the internship and guidance.
