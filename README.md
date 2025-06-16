# Sniff & Shield IDPS

A simple web-based Intrusion Detection and Prevention System (IDPS) built with Flask.

This application provides a user interface to analyze network events for potential threats based on signature and anomaly detection.

## Features

-   **Signature-Based Detection:** Identifies known malicious patterns in network payloads.
-   **Anomaly-Based Detection:** Flags unusual network activity (e.g., very large packet sizes).
-   **Web Interface:** An easy-to-use interface to input and analyze network event data.
-   **Live Intrusion Log:** Displays a log of all detected intrusions.
-   **Modern UI:** A sleek, responsive cybersecurity-themed interface.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/AjayPrajapati83/IDS.git
    cd IDS
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    # On Windows, use: venv\Scripts\activate
    # On macOS/Linux, use: source venv/bin/activate
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  **Run the Flask application:**
    ```bash
    python idps.py
    ```

2.  **Open your web browser** and navigate to `http://127.0.0.1:5000`.

3.  **Enter the network event details** in the form and click "Analyze Event" to see the detection results.
