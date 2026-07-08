OTscope — Quick-Start Guide
===========================

REQUIREMENTS
  - Python 3.8 or later  (https://www.python.org/downloads/)
    When installing on Windows, check "Add Python to PATH".
  - tshark 4.6.4 or later  (https://www.wireshark.org/download.html)
    When installing Wireshark on Windows, make sure TShark is included.

FIRST-TIME SETUP
  1. Open a terminal (Command Prompt or PowerShell on Windows).
  2. Navigate to the folder that contains otscope.py:
       cd C:\OTscope
  3. Install Python dependencies (one time only):
       pip install -r requirements.txt

RUNNING AN ANALYSIS
  1. Drop your .pcap or .pcapng capture files into the  pcaps\  folder.
  2. Run OTscope:
       python otscope.py
  3. Follow the on-screen prompts (assessor name, site name, etc.).
  4. When analysis completes, reports appear in the  output\  folder.

QUICK REFERENCE
  python otscope.py                          Interactive mode (recommended)
  python otscope.py --scan pcaps\            Auto-scan, no prompts
  python otscope.py --offline                Disable all outbound network calls
  python otscope.py --version                Show version

OUTPUT FILES
  output\OT_PCAP_Analysis_<site>_<date>.docx   Word report
  output\OT_PCAP_Analysis_<site>_<date>.json   Machine-readable findings
  output\OTscope_Purdue_Summary_<site>_<date>.svg  Network diagram (all devices)
  output\OTscope_Purdue_Detail_<site>_<date>.svg   Network diagram (<=50 devices)

FULL DOCUMENTATION
  See OTscope_User_Guide.pdf for the complete operator manual.
