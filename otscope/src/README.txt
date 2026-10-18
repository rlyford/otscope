OTscope — Quick-Start Guide
===========================

REQUIREMENTS
  - Python 3.8 or later, tested with 3.14  (https://www.python.org/downloads/)
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
  1. Drop your capture files into the  pcaps\  folder.  OTscope reads .pcap,
     .pcapng, and .cap files, including gzip-compressed ones (.pcap.gz, ...).
     Capture files left next to otscope.py are moved into pcaps\ on the next run.
  2. Run OTscope:
       python otscope.py
  3. Follow the on-screen prompts (assessor name, site name, etc.).
  4. When analysis completes, OTscope prints a summary -- findings by severity,
     how much of the traffic it could assess, the first actions to take, and
     the files written -- and offers to open the Word report.  Reports appear
     in the  output\  folder; earlier reports are never overwritten.

CONTINUING LATER
  Run  python otscope.py  and answer  R  to resume a saved session (review its
  findings or regenerate the report) or  A  to add new captures to it.  OTscope
  lists the saved sessions in  output\  -- pick one by number or name.

QUICK REFERENCE
  python otscope.py                          Interactive mode (recommended)
  python otscope.py --scan pcaps\            Auto-scan, no prompts
  python otscope.py --offline                Disable all outbound network calls
  python otscope.py --verbose                Show every protocol check's result
  python otscope.py --version                Show version

OUTPUT FILES
  output\OT_PCAP_Analysis_<site>_<date>.docx        Word report
  output\OT_PCAP_Analysis_<site>_<date>.json        Machine-readable findings
  output\OT_Device_Inventory_<site>_<date>.csv      Every observed device
  output\OT_Flow_Allowlist_<site>_<date>.csv        Observed client/server/port flows
  output\OTscope_Purdue_Summary_<site>_<date>.svg   Network diagram (all devices)
  output\OTscope_Purdue_Detail_<site>_<date>.svg    Network diagram (<=50 devices)
  output\<site>_<date>.otpa_session                 Session file (resume / add pcaps)

SITE-SPECIFIC PROTOCOLS
  A site's own OT protocols (for example a DCS vendor's engineering port) can be
  added to the config file  %USERPROFILE%\.ot_pcap_analyzer.conf  under
  "custom_ot_protocols" -- see the User Guide, section 6.3.1.

FULL DOCUMENTATION
  See OTscope_User_Guide (.md or .pdf) in this package for the complete operator manual.
