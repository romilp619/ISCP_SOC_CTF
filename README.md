A simple, efficient Python script for detecting and redacting Personally Identifiable Information (PII) in structured data. Designed for e-commerce platforms or any system handling sensitive user data, this tool helps prevent data leaks by identifying and masking PII elements like phone numbers, Aadhaar cards, passports, UPI IDs, and more. It processes CSV files containing JSON-formatted records, adds a PII flag, and outputs a redacted version—perfect for compliance with privacy regulations like GDPR or India's DPDP Act.
Why This Tool?
In today's data-driven world, accidental PII exposure through logs, APIs, or internal tools can lead to fraud and privacy breaches. This script acts as a "guardian" layer, automatically scanning and sanitizing data without heavy dependencies or latency overhead. It's lightweight, customizable, and easy to integrate into your workflow.
Key Features

Standalone PII Detection: Instantly spots phone numbers (10-digit), Aadhaar (12-digit), passports (alphanumeric formats), and UPI IDs (e.g., user@upi).
Combinatorial PII Detection: Identifies sensitive combos like full name + email, name + address, or device ID/IP with user context—only redacts when multiple factors are present to avoid false positives.
Smart Redaction: Masks data intelligently (e.g., phone as 98XXXXXX21, email as jXXX@domain.com) while preserving non-PII for usability.
Efficient Processing: Uses regex for quick checks; handles large CSVs with progress updates and error tolerance.
Output: Generates a new CSV with record ID, redacted JSON, and a boolean is_pii flag.
No External Dependencies Beyond Basics: Relies on re, json, pandas, and standard libs—runs anywhere Python does.

Requirements

Python 3.6 or higher
Pandas library (install via pip install pandas)

Installation

Clone the repo:
git clone https://github.com/romilp619/ISCP_SOC_CTF
cd ISCP_SOC_CTF

Install dependencies:
pip install pandas


Usage
Run the script on your input CSV file:
python pii_redactor.py path/to/input.csv

Input Format: CSV with columns record_id (int/string) and data_json (JSON string containing key-value pairs).
Output: A file named pii_redacted_output.csv in the current directory.
Example Input Row:
record_id,data_json
1,"{""name"": ""John Doe"", ""phone"": ""9876543210"", ""email"": ""john@example.com""}"

Example Output Row:
textrecord_id,redacted_data_json,is_pii
1,"{""name"": ""JXXX DXX"", ""phone"": ""98XXXXXX10"", ""email"": ""jXXX@example.com""}",True


The script processes rows one by one, logging progress every 100 records. If errors occur (e.g., invalid JSON), it skips redaction and flags as non-PII.
How It Works

Detection:

Standalone: Regex-based checks for primary PII fields.
Combinatorial: Scans for secondary fields (name, email, etc.) and only flags if 2+ are combined (e.g., name + address).


Redaction:

Applies field-specific masking to obscure data while keeping format intact.


Processing:

Loads CSV with Pandas.
Analyzes each JSON row using the PIIRedactor class.
Outputs redacted CSV.




