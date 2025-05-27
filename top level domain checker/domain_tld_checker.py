import csv
import whois # For WHOIS lookups
import dns.resolver # For DNS lookups
import tldextract # For accurately extracting base domain names
import time
import socket # For specific network exceptions

# --- Configuration ---
# List of TLDs to check against. Feel free to add or remove TLDs.
TLDS_TO_CHECK = [
    '.com', '.org', '.net', '.co', '.info', '.biz', '.us', '.ca', '.uk',
    '.io', '.ai', '.tech', '.app', '.online', '.site', '.website', '.space',
    '.store', '.xyz', '.club', '.vip', '.link', '.click', '.top', '.loan',
    '.support', '.help', '.services', '.company', '.solutions', '.agency',
    '.email', '.cc', '.tv', '.me', '.asia', '.mobi', '.pro', '.name',
    '.de', '.fr', '.au', '.nl', '.ru', '.cn', '.br', '.in', '.jp', # Common ccTLDs
    '.live', '.shop', '.world', '.guru', '.news', '.today', '.ltd', '.group'
]
# Ensure unique and sorted TLDs, all starting with a dot.
TLDS_TO_CHECK = sorted(list(set([tld if tld.startswith('.') else '.' + tld for tld in TLDS_TO_CHECK])))


def extract_meaningful_base(fqdn):
    """
    Extracts the meaningful part of the domain before the public suffix.
    e.g., 'sub.example.com' -> 'sub.example'
          'example.com' -> 'example'
          'l.vt.com' (if 'com' is suffix) -> 'l.vt'
    """
    ext = tldextract.extract(fqdn.lower().strip())
    if ext.subdomain:
        # If there are multiple levels of subdomains, include them all with the domain
        return f"{ext.subdomain}.{ext.domain}"
    return ext.domain


def get_domain_variant_info(domain_variant):
    """
    Gathers DNS and WHOIS information for a given domain variant.
    """
    info = {
        "Full Domain Queried": domain_variant,
        "DNS Resolves (A/AAAA)": "No",
        "IP Addresses": "N/A",
        "Name Servers (NS)": "N/A",
        "Mail Servers (MX)": "N/A",
        "WHOIS Creation Date": "N/A",
        "WHOIS Updated Date": "N/A",
        "WHOIS Expiration Date": "N/A",
        "WHOIS Registrar": "N/A",
        "WHOIS Domain Status": "N/A",
        "WHOIS Registrant Org": "N/A",
        "WHOIS Notes/Errors": ""
    }
    dns_errors = []
    whois_errors = []
    dns_resolved_ip = False
    dns_resolved_ns = False

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.5 # Slightly increased timeout
    resolver.lifetime = 2.5

    # 1. Check A/AAAA records (IP Addresses)
    ip_addresses_list = []
    try:
        for rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
            answers = resolver.resolve(domain_variant, rdtype)
            for rdata in answers:
                ip_addresses_list.append(rdata.to_text())
        if ip_addresses_list:
            info["IP Addresses"] = ", ".join(sorted(list(set(ip_addresses_list))))
            info["DNS Resolves (A/AAAA)"] = "Yes"
            dns_resolved_ip = True
    except dns.resolver.NXDOMAIN:
        dns_errors.append("DNS NXDOMAIN (IP)")
    except dns.resolver.NoAnswer:
        dns_errors.append("DNS NoAnswer (IP)")
    except dns.exception.Timeout:
        dns_errors.append("DNS Timeout (IP)")
    except Exception as e:
        dns_errors.append(f"DNS IP Error: {type(e).__name__}")

    # 2. Check NS records (Name Servers)
    name_servers_list = []
    try:
        answers = resolver.resolve(domain_variant, dns.rdatatype.NS)
        for rdata in answers:
            name_servers_list.append(rdata.target.to_text().rstrip('.'))
        if name_servers_list:
            info["Name Servers (NS)"] = ", ".join(sorted(list(set(name_servers_list))))
            dns_resolved_ns = True
    except dns.resolver.NXDOMAIN:
        if not dns_resolved_ip: dns_errors.append("DNS NXDOMAIN (NS)") # Only relevant if IP also NXDOMAIN
    except dns.resolver.NoAnswer:
        dns_errors.append("DNS NoAnswer (NS)")
    except dns.exception.Timeout:
        dns_errors.append("DNS Timeout (NS)")
    except Exception as e:
        dns_errors.append(f"DNS NS Error: {type(e).__name__}")

    # 3. Check MX records (Mail Servers)
    mail_servers_list = []
    try:
        answers = resolver.resolve(domain_variant, dns.rdatatype.MX)
        for rdata in answers:
            mail_servers_list.append(f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}")
        if mail_servers_list:
            # Sort by preference, then by name
            mail_servers_list.sort(key=lambda x: (int(x.split()[0]), x.split()[1]))
            info["Mail Servers (MX)"] = ", ".join(mail_servers_list)
    except dns.resolver.NXDOMAIN:
        if not dns_resolved_ip and not dns_resolved_ns : dns_errors.append("DNS NXDOMAIN (MX)")
    except dns.resolver.NoAnswer:
        dns_errors.append("DNS NoAnswer (MX)")
    except dns.exception.Timeout:
        dns_errors.append("DNS Timeout (MX)")
    except Exception as e:
        dns_errors.append(f"DNS MX Error: {type(e).__name__}")

    # 4. WHOIS Lookup
    # Proceed if there's any sign of DNS activity or to check availability explicitly
    if dns_resolved_ip or dns_resolved_ns or not any("NXDOMAIN (IP)" in e and "NXDOMAIN (NS)" in e for e in dns_errors):
        try:
            w = whois.whois(domain_variant) # Can be slow
            if w and (w.domain_name or w.get('domain_name') or w.text): # check if any data was returned

                def get_val(data_obj, attr_name, is_list=False, is_date=False):
                    val = None
                    if hasattr(data_obj, attr_name):
                        val = getattr(data_obj, attr_name)
                    elif isinstance(data_obj, dict): # some parsers might return dict-like
                        val = data_obj.get(attr_name)

                    if val:
                        if isinstance(val, list):
                            if not val: return "N/A"
                            # For dates in list, take the first one. For statuses, join them.
                            return str(val[0]) if is_date and val else ", ".join(sorted(list(set(str(v).strip() for v in val if v))))
                        return str(val).strip()
                    return "N/A"

                info["WHOIS Creation Date"] = get_val(w, 'creation_date', is_date=True)
                info["WHOIS Updated Date"] = get_val(w, 'updated_date', is_date=True)
                info["WHOIS Expiration Date"] = get_val(w, 'expiration_date', is_date=True)
                info["WHOIS Registrar"] = get_val(w, 'registrar')
                info["WHOIS Domain Status"] = get_val(w, 'status', is_list=True) # status often a list

                registrant_org = get_val(w, 'org')
                if registrant_org == "N/A": # Try another common attribute name
                    registrant_org = get_val(w, 'registrant_organization')
                info["WHOIS Registrant Org"] = registrant_org

                if (get_val(w, 'domain_name') == "N/A" or not get_val(w, 'domain_name')) and not (dns_resolved_ip or dns_resolved_ns):
                    whois_errors.append("WHOIS data sparse or domain may be available.")
                elif not (dns_resolved_ip or dns_resolved_ns): # WHOIS found, but no active DNS
                    whois_errors.append("WHOIS found, but no active DNS (A/AAAA or NS).")

            else: # WHOIS object 'w' is None or has no domain_name (often indicates not found)
                if not (dns_resolved_ip or dns_resolved_ns):
                    whois_errors.append("Domain likely not registered (WHOIS empty/no match).")
                else:
                    whois_errors.append("DNS resolves, but WHOIS lookup failed or returned no data.")

        except whois.parser.PywhoisError as e:
            err_str = str(e).lower()
            if any(s in err_str for s in ["no match", "not found", "no entries", "available", "invalid query"]):
                whois_errors.append("WHOIS: No match/Not found (likely available or invalid query).")
            else:
                whois_errors.append(f"WHOIS Error: {str(e)[:100]}") # Keep error message concise
        except ConnectionResetError:
            whois_errors.append("WHOIS Error: ConnectionResetError")
        except socket.timeout:
             whois_errors.append("WHOIS Error: Socket Timeout")
        except AttributeError as e: # If whois object doesn't have expected attributes
            whois_errors.append(f"WHOIS AttrError: {str(e)[:50]} (data structure unexpected)")
        except Exception as e:
            whois_errors.append(f"WHOIS General Error: {type(e).__name__} - {str(e)[:50]}")
    else: # No significant DNS record found (e.g. NXDOMAIN on IP and NS)
        whois_errors.append("Skipped WHOIS due to DNS indicating non-existence.")


    all_notes = []
    if dns_errors: all_notes.append("DNS: " + "; ".join(sorted(list(set(dns_errors)))))
    if whois_errors: all_notes.append("WHOIS: " + "; ".join(sorted(list(set(whois_errors)))))
    info["WHOIS Notes/Errors"] = " | ".join(all_notes) if all_notes else "OK"

    return info


def main():
    input_file = input("Enter the path to your input file (one domain per line): ")
    output_file = input("Enter the path for your output CSV file: ")

    output_header = [
        "Original Input Domain", "Base Name Extracted", "TLD Variant Checked", "Full Domain Queried",
        "DNS Resolves (A/AAAA)", "IP Addresses", "Name Servers (NS)", "Mail Servers (MX)",
        "WHOIS Creation Date", "WHOIS Updated Date", "WHOIS Expiration Date", "WHOIS Registrar",
        "WHOIS Domain Status", "WHOIS Registrant Org", "WHOIS Notes/Errors"
    ]
    results_data = []

    try:
        with open(input_file, 'r', encoding='utf-8') as f_in:
            original_domains = [line.strip() for line in f_in if line.strip()]
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return
    except Exception as e:
        print(f"Error reading input file: {e}")
        return

    if not original_domains:
        print("Input file is empty or contains no valid domain lines.")
        return

    print(f"Found {len(original_domains)} base domains to process from '{input_file}'.")
    total_variants_to_check = len(original_domains) * len(TLDS_TO_CHECK)
    print(f"Checking {len(TLDS_TO_CHECK)} TLDs for each, approx. {total_variants_to_check} total queries.")
    current_query_num = 0

    for orig_domain in original_domains:
        base_name = extract_meaningful_base(orig_domain)
        if not base_name:
            print(f"Warning: Could not extract a valid base name from '{orig_domain}'. Skipping.")
            results_data.append({
                "Original Input Domain": orig_domain, "Base Name Extracted": "Error",
                "WHOIS Notes/Errors": "Could not extract base name from input."
            })
            continue

        print(f"\nProcessing base: '{base_name}' (from '{orig_domain}')")
        for tld in TLDS_TO_CHECK:
            current_query_num += 1
            domain_variant_to_check = base_name + tld # tld already includes '.'
            
            print(f"({current_query_num}/{total_variants_to_check}) Checking: {domain_variant_to_check}...")
            
            variant_info = get_domain_variant_info(domain_variant_to_check)
            
            # Prepare row for CSV
            row = {
                "Original Input Domain": orig_domain,
                "Base Name Extracted": base_name,
                "TLD Variant Checked": tld,
            }
            row.update(variant_info) # Add all keys from variant_info
            results_data.append(row)
            
            time.sleep(0.8) # BE POLITE to servers! Increase if you hit rate limits.

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f_out:
            writer = csv.DictWriter(f_out, fieldnames=output_header)
            writer.writeheader()
            writer.writerows(results_data)
        print(f"\nSuccessfully wrote all results to '{output_file}'")
    except IOError as e:
        print(f"\nError writing results to output file '{output_file}': {e}")
    except Exception as e:
        print(f"\nAn unexpected error occurred while writing the CSV: {e}")

    print(f"""
    ---
    Disclaimer:
    This script provides data based on public DNS and WHOIS records.
    It CANNOT definitively determine if a site is a phishing site.
    The gathered information (e.g., recent registration, privacy services,
    different registrar/hosting details than a known legitimate site) should be
    used as INDICATORS for further manual investigation by a security professional.
    WHOIS data can be inaccurate, incomplete, or masked due to privacy services.
    DNS records indicate configuration, not necessarily malicious intent.
    ---
    Remember to have the necessary libraries installed:
    pip install python-whois dnspython tldextract
    ---
    """)

if __name__ == "__main__":
    main()