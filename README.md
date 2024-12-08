# Intrusion Detection System With XGBoost Model
[Dataset from..](https://www.kaggle.com/datasets/wardac/applicationlayer-ddos-dataset/data)

IDS program for Application Layer DDoS Attack.

## Features
- Network Traffic Capture: Captures real-time packets from a specified network interface.
- Flow Data Storage: Processes captured packets into flow features and stores them in a CSV file.
- Intrusion Detection: Leverages an XGBoost model to analyze flow data and detect anomalies or malicious behavior.
- Logging: Saves detection results in a log file for tracking and analysis.

## Usage
`sudo python3 ids.py <interface>`
