# Real-Time Network Traffic Analysis Using Machine Learning

## Overview

This project is a comprehensive network traffic analysis tool built with Python. It provides a graphical user interface (GUI) to monitor network traffic in real-time or to analyze existing packet capture (PCAP) files. The core of the application is a dual-engine anomaly detection system that combines a pre-trained Random Forest machine learning model with a flexible rule-based engine to identify various types of network threats and suspicious activities.

The tool is designed for network administrators, security analysts, and students who wish to gain insights into their network, identify potential security threats, and understand the practical application of machine learning in cybersecurity.

---

## Features

-   **Live Packet Capture**: Sniff packets in real-time from any network interface on the host machine.
-   **PCAP File Analysis**: Import and analyze `.pcap` files for offline analysis.
-   **Dual Detection Engine**:
    -   **Machine Learning-Based Detection**: Utilizes a Random Forest model trained on the CICIDS-2017 dataset to classify network flows and detect complex anomalies like DoS, DDoS, Port Scanning, and Web Attacks.
    -   **Rule-Based Detection**: Implements a set of predefined rules to catch common and clear-cut threats, such as high-rate ICMP floods, suspicious port access, and port scanning behavior.
-   **Interactive GUI**: A user-friendly interface built with Tkinter and the `sv_ttk` theme, featuring:
    -   A live feed of all captured packets.
    -   A dedicated log for anomalous flows, detailing the detection method (ML or Rule-Based) and the reason for the alert.
    -   Real-time system monitoring (CPU and RAM).
    -   Detailed header information for any selected packet.
-   **Comprehensive Reporting**:
    -   Generate a detailed report page after a capture session, with summary statistics and visualizations.
    -   A pie chart showing the distribution of network protocols.
    -   A filterable log of all captured packets, with anomalies highlighted.
    -   A list of the most frequent network flows.
-   **Flexible Data Export**:
    -   Export all captured packets to a PCAP file for analysis in other tools like Wireshark.
    -   Export all processed flow features (for both normal and anomalous flows) to a detailed CSV file.
    -   Save the final report summary as a text file.
-   **Model Training and Extensibility**:
    -   Includes a script to retrain the machine learning model with updated data or different parameters.
    -   The rule-based engine is easily extensible, allowing new detection rules to be added.

---

## How It Works

1.  **User Choice**: The user starts on the **Home Page** and chooses between live monitoring or importing a PCAP file.

2.  **Capture/Import**:
    -   For live monitoring, the `PacketCaptureManager` uses **Scapy** to sniff packets on the selected interface.
    -   For file import, it reads all packets from the PCAP file using **Scapy's `rdpcap`**.

3.  **Packet Processing Pipeline** (for both live and imported data):
    -   Each packet is passed to the **`RuleBasedDetector`**, which immediately checks it against a list of predefined rules. If a rule is triggered, an anomaly is logged instantly.
    -   Simultaneously, the packet is sent to the **`FlowFeatureExtractor`**, which groups packets into network flows.
    -   When a flow is considered complete (based on a timeout), the extractor calculates over 50 statistical features (e.g., duration, packet sizes, inter-arrival times).

4.  **Machine Learning Detection**:
    -   The feature set for each completed flow is passed to the **`AnomalyDetector`**.
    -   The detector uses a pre-trained **RobustScaler** to normalize the features and then feeds them into the **Random Forest model** for prediction.
    -   The model classifies the flow and assigns an anomaly score.

5.  **GUI Updates**:
    -   Live packets and detected anomalies are sent to the **Monitor Page** for real-time display.
    -   For PCAP analysis, a **Processing Window** with a progress bar is shown. Once complete, the data is passed to the **Report Page**.

6.  **Reporting and Export**: After a session, the user can view the comprehensive report or export the captured data in various formats (PCAP, CSV, TXT).

---

## Project Structure

The project is organized into a `Src` directory containing the main application logic and a `utils` sub-directory for backend components.

```
networkTraffic/
│
├── Src/
│   ├── main.py                     # Main application entry point
│   ├── pages/
│   │   ├── home.py                 # The home screen GUI
│   │   ├── monitor.py              # The live monitoring GUI
│   │   ├── processing_window.py    # The progress bar pop-up for PCAP analysis
│   │   └── report.py               # The final report page GUI
│   └── utils/
│       ├── anomaly_detector.py         # Handles ML-based anomaly detection
│       ├── flow_feature_extractor.py # Extracts features from packet flows
│       ├── model_trainer.py          # Script to train the ML model
│       ├── packet_capture_manager.py # Core engine for packet processing
│       └── rule_based_detector.py    # Handles rule-based anomaly detection
│
├── ml_models/                        # Directory for trained models and scalers
│
├── ddos_tester.py                    # Script for testing DoS detection
├── requirements.txt                  # Required Python packages
└── README.md                         # Project documentation
```

---

## Setup and Installation

1.  **Clone the Repository**:
    ```bash
    git clone <your-repository-url>
    cd networkTraffic
    ```

2.  **Create a Virtual Environment** (Recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install Dependencies**:
    Make sure you have `Npcap` (for Windows) or `libpcap` (for macOS/Linux) installed for Scapy to function correctly. Then, install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```


## Usage

### Running the Application

To start the application, run the `main.py` script from the project root:
```bash
python Src/main.py
```

### Live Monitoring

1.  Launch the application.
2.  Select an active network interface from the dropdown menu on the Home Page.
3.  Click the **"Start Live Monitoring"** button.
4.  The application will switch to the Monitor Page and begin displaying live traffic and any detected anomalies.
5.  Use the buttons at the bottom to stop/resume capture, export data, or generate a final report.

### Analyzing a PCAP File

1.  Launch the application.
2.  Click the **"Import and Analyze PCAP File"** button.
3.  Select a `.pcap` file from your system.
4.  A processing window will appear, showing the analysis progress.
5.  Once complete, the application will automatically switch to the Report Page, populated with the analysis results from the file.

---

## Testing the Detection Engine

A simple UDP flood script (`ddos.py`) is included to help you test the rule-based DoS detection.

1.  Start the main application and begin monitoring the **Loopback** interface (e.g., "Loopback Pseudo-Interface 1" on Windows).
2.  Open a **new terminal**, navigate to the project directory, and run the test script:
    ```bash
    # Basic usage: targets localhost on port 8080 for 10 seconds
    python ddos_tester.py 127.0.0.1 8080
    ```
3.  Confirm the test by typing `yes` when prompted.
4.  Observe the "Anomalous Flows" table in the monitoring window. You should see "High Packet Rate (DoS suspected)" alerts appear.
