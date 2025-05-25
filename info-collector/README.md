# Domain Information Collector

## Description

This Python script automates the process of gathering public WHOIS and DNS (A/AAAA, MX records) information for a list of domain names provided in a CSV file. It then outputs this information into another CSV file. This tool can be useful for brand monitoring, security research, or initial data gathering for domain analysis.

## Features

* **Bulk Domain Processing**: Reads domain names from an input CSV file.
* **WHOIS Lookup**: Retrieves domain registration details including:
    * Domain Name
    * Registry Domain ID
    * Registrar WHOIS Server, URL, Name, IANA ID
    * Important Dates (Updated, Creation, Expiration)
    * Domain Status
    * Name Servers
    * Registrar Abuse Contact Email and Phone (if available)
    * Registrant, Admin, and Tech contact details (if available and not obscured by privacy services)
* **DNS Lookup**:
    * Retrieves A and AAAA records (IP addresses) for the domain.
    * Retrieves MX records (mail exchange servers) for the domain.
* **Error Handling**: Manages common errors during WHOIS and DNS lookups (e.g., domain not found, no records, timeouts, attribute errors).
* **Politeness Delay**: Includes a configurable delay between requests to avoid overwhelming servers.
* **CSV Output**: Saves all collected information in a structured CSV format.
* **Basic Domain Validation**: Checks for obviously invalid domain formats before processing.

## Requirements

* Python 3.x
* The following Python libraries:
    * `python-whois`
    * `dnspython`

You can install the required libraries using pip:
```bash
pip install python-whois dnspython
```

## How to Use

1. **Prepare your input CSV file**: Create a CSV file (e.g., `domains.csv`) with one domain name per row in the first column.

2. **Run the script**: Execute the `domain_info_collector.py` script from your terminal:
```bash
python domain_info_collector.py
```

3. **Enter file paths**:
    * The script will prompt you to enter the path to your input CSV file.
    * Then, it will prompt you to enter the desired path for the output CSV file (e.g., `domain_details.csv`).

4. **Processing**: The script will then process each domain, printing progress to the console.

5. **Check results**: Once finished, the script will notify you. The collected information will be in the specified output CSV file.

## Input CSV Format

The input CSV file should have the domain names listed in the first column. The script expects one domain per row.

**Example (`input_domains.csv`)**:
```
google.com
example.com
yourdomain.net
```

## Output CSV Format

The output CSV file will contain two columns: `Domain` and `Information`.

* **Domain**: The domain name processed.
* **Information**: A multi-line string containing all the gathered WHOIS and DNS details for that domain, or error messages if issues were encountered.

**Example (`output_details.csv` snippet)**:
```
Domain,Information
google.com,"Domain Name: GOOGLE.COM
Registry Domain ID: 2138514_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: https://www.markmonitor.com
...
Server IP (A/AAAA): 172.217.160.142, 2404:6800:4001:802::200e
Mail Server (MX): 10 smtp.google.com."
example.com,"Domain Name: EXAMPLE.COM
...
Server IP (A/AAAA): 93.184.216.34
Mail Server (MX): No MX record found"
```

## Error Handling and Notes

* **WHOIS Data Variability**: The structure and availability of WHOIS data can vary significantly between registrars and TLDs. Some information might be "N/A" if not provided or hidden.
* **Privacy Services**: Many domains use privacy services (e.g., "Domains By Proxy"), which will mask the actual registrant's contact details. The script reports what is publicly available.
* **Rate Limiting**: Performing many queries quickly can lead to temporary blocks from WHOIS or DNS servers. The script includes a 0.75 second delay by default. If processing a very large number of domains, you might need to increase this delay (by editing the `time.sleep()` value in the `process_csv_files` function) or implement more robust rate-limiting handling.
* **DNS Errors**: The script will report DNS errors such as NXDOMAIN (domain does not exist), NoAnswer (no record of the queried type), or Timeout.
* **Invalid Domain Formats**: The script performs a basic check for invalid domain formats and will skip them, noting this in the output CSV.

## Example

**Create `my_domains.csv`**:
```
github.com
fakedomainthatshouldnotexist12345.org
```

**Run the script**:
```bash
python domain_info_collector.py
```

* Enter `my_domains.csv` when prompted for the input file.
* Enter `results.csv` when prompted for the output file.
* Check `results.csv` for the collected data. You'll see detailed info for `github.com` and error messages (like NXDOMAIN) for `fakedomainthatshouldnotexist12345.org`.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
