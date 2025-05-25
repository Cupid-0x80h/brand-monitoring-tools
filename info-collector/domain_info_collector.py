import csv
import whois # For WHOIS lookups
import dns.resolver # For DNS lookups (MX, A/AAAA records)
import time
import socket # For potential socket errors

def get_domain_info(domain_name):
    """
    Gathers WHOIS, DNS (A/AAAA, MX) information for a given domain.
    Returns a formatted string with all information.
    """
    info_parts = []
    errors = []

    # --- WHOIS Lookup ---
    try:
        w = whois.whois(domain_name)
        if w:
            if w.domain_name: # Check if WHOIS lookup was successful at all
                info_parts.append(f"Domain Name: {w.domain_name if isinstance(w.domain_name, str) else ', '.join(w.domain_name)}")
                info_parts.append(f"Registry Domain ID: {w.registry_domain_id if w.registry_domain_id else 'N/A'}")
                info_parts.append(f"Registrar WHOIS Server: {w.whois_server if w.whois_server else 'N/A'}")

                registrar_url = 'N/A'
                if hasattr(w, 'registrar_url') and w.registrar_url:
                    registrar_url = w.registrar_url
                elif w.registrar:
                    # Attempt to construct a common URL format
                    main_registrar_name = w.registrar.split(',')[0].lower().replace(' ', '').replace('.', '')
                    if main_registrar_name:
                        registrar_url = f"https://www.{main_registrar_name}.com" # Common but not guaranteed
                info_parts.append(f"Registrar URL: {registrar_url}")

                # Dates can be single values or lists; take the first if a list
                updated_date = w.updated_date
                if isinstance(updated_date, list): updated_date = updated_date[0] if updated_date else None
                info_parts.append(f"Updated Date: {str(updated_date) if updated_date else 'N/A'}")

                creation_date = w.creation_date
                if isinstance(creation_date, list): creation_date = creation_date[0] if creation_date else None
                info_parts.append(f"Creation Date: {str(creation_date) if creation_date else 'N/A'}")

                expiration_date = w.expiration_date
                if isinstance(expiration_date, list): expiration_date = expiration_date[0] if expiration_date else None
                info_parts.append(f"Registrar Registration Expiration Date: {str(expiration_date) if expiration_date else 'N/A'}")

                info_parts.append(f"Registrar: {w.registrar if w.registrar else 'N/A'}")
                info_parts.append(f"Registrar IANA ID: {w.iana_id if hasattr(w, 'iana_id') and w.iana_id else 'N/A'}")

                # Abuse contacts might be parsed by some configurations of python-whois or specific TLDs
                info_parts.append(f"Registrar Abuse Contact Email: {w.abuse_contact_email if hasattr(w, 'abuse_contact_email') and w.abuse_contact_email else 'N/A'}")
                info_parts.append(f"Registrar Abuse Contact Phone: {w.abuse_contact_phone if hasattr(w, 'abuse_contact_phone') and w.abuse_contact_phone else 'N/A'}")

                if isinstance(w.status, list):
                    info_parts.append(f"Domain Status: {', '.join(w.status) if w.status else 'N/A'}")
                else:
                    info_parts.append(f"Domain Status: {str(w.status) if w.status else 'N/A'}")
                
                # Registrant/Tech info (often masked by privacy services)
                # The python-whois library provides what it can parse.
                # Detailed street/city breakdown like your example is highly registrar-dependent
                # and often not available as separate attributes.
                for contact_type_prefix in ['registrant', 'admin', 'tech']:
                    name = getattr(w, f"{contact_type_prefix}_name", None) or getattr(w, "name", None) if contact_type_prefix == 'registrant' else getattr(w, f"{contact_type_prefix}_name", None)
                    org = getattr(w, f"{contact_type_prefix}_organization", None) or getattr(w, "org", None) if contact_type_prefix == 'registrant' else getattr(w, f"{contact_type_prefix}_organization", None)
                    email = getattr(w, f"{contact_type_prefix}_email", None)
                    # Address details are usually in w.address, w.city etc. if parsed, or part of raw text
                    
                    # For simplicity, we'll report common fields if available
                    if name: info_parts.append(f"{contact_type_prefix.capitalize()} Name: {name}")
                    if org: info_parts.append(f"{contact_type_prefix.capitalize()} Organization: {org}")
                    # You might want to add more specific fields if `python-whois` consistently parses them for your target domains
                    # e.g. street, city, country, phone
                    if email: info_parts.append(f"{contact_type_prefix.capitalize()} Email: {email}")


                if w.name_servers:
                    info_parts.append(f"Name Server: {', '.join(w.name_servers)}")
                else:
                    info_parts.append("Name Server: N/A")
            else: # w exists but w.domain_name is None (lookup failed partially)
                info_parts.append("WHOIS information incomplete or lookup failed.")
                if hasattr(w, 'text') and w.text:
                     info_parts.append(f"Raw WHOIS response might contain partial data or error message.")

        else: # w is None
            info_parts.append("WHOIS lookup failed to return any data.")
            errors.append(f"WHOIS lookup failed for {domain_name}")

    except whois.parser.PywhoisError as e:
        info_parts.append(f"WHOIS Error: {e}")
        errors.append(f"WHOIS lookup error for {domain_name}: {e}")
    except AttributeError as e: # Handles cases where expected attributes are missing from w object
        info_parts.append(f"WHOIS Attribute Error: {e} (data might be incomplete or structured differently)")
        errors.append(f"WHOIS attribute error for {domain_name}: {e}")
    except Exception as e:
        info_parts.append(f"WHOIS General Error: {e}")
        errors.append(f"General WHOIS processing error for {domain_name}: {e}")

    # --- DNS Lookups ---
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    # A/AAAA Records (IP Addresses)
    ip_addresses = []
    try:
        for rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
            answers = resolver.resolve(domain_name, rdtype)
            for rdata in answers:
                ip_addresses.append(rdata.to_text())
        info_parts.append(f"Server IP (A/AAAA): {', '.join(ip_addresses) if ip_addresses else 'No A/AAAA record found'}")
    except dns.resolver.NXDOMAIN:
        info_parts.append("Server IP (A/AAAA): NXDOMAIN (Domain does not exist)")
        errors.append(f"DNS NXDOMAIN for {domain_name} (A/AAAA)")
    except dns.resolver.NoAnswer:
        info_parts.append("Server IP (A/AAAA): No A/AAAA record found")
        errors.append(f"DNS NoAnswer for {domain_name} (A/AAAA)")
    except dns.exception.Timeout:
        info_parts.append("Server IP (A/AAAA): DNS Timeout")
        errors.append(f"DNS Timeout for {domain_name} (A/AAAA)")
    except Exception as e:
        info_parts.append(f"Server IP (A/AAAA) Error: {e}")
        errors.append(f"DNS A/AAAA lookup error for {domain_name}: {e}")

    # MX Records (Mail Servers)
    mail_servers = []
    try:
        answers = resolver.resolve(domain_name, dns.rdatatype.MX)
        for rdata in answers:
            mail_servers.append(f"{rdata.preference} {rdata.exchange.to_text()}")
        info_parts.append(f"Mail Server (MX): {', '.join(mail_servers) if mail_servers else 'No MX record found'}")
    except dns.resolver.NXDOMAIN:
        info_parts.append("Mail Server (MX): NXDOMAIN (Domain does not exist)")
        errors.append(f"DNS NXDOMAIN for {domain_name} (MX)")
    except dns.resolver.NoAnswer:
        info_parts.append("Mail Server (MX): No MX record found")
        errors.append(f"DNS NoAnswer for {domain_name} (MX)")
    except dns.exception.Timeout:
        info_parts.append("Mail Server (MX): DNS Timeout")
        errors.append(f"DNS Timeout for {domain_name} (MX)")
    except Exception as e:
        info_parts.append(f"Mail Server (MX) Error: {e}")
        errors.append(f"DNS MX lookup error for {domain_name}: {e}")
    
    if not info_parts and errors: # If only errors occurred
        return "Error gathering information:\n" + "\n".join(errors)
    elif errors: # If some info and some errors
        return "\n".join(info_parts) + "\n\nEncountered issues:\n" + "\n".join(errors)
    
    return "\n".join(info_parts)


def process_csv_files(input_filepath, output_filepath):
    """
    Reads domains from input_filepath, gathers info, and writes to output_filepath.
    """
    try:
        with open(input_filepath, 'r', newline='', encoding='utf-8') as infile, \
             open(output_filepath, 'w', newline='', encoding='utf-8') as outfile:
            
            reader = csv.reader(infile)
            writer = csv.writer(outfile)
            
            writer.writerow(['Domain', 'Information']) # Write header
            
            print(f"Starting to process domains from: {input_filepath}")
            print(f"Results will be saved to: {output_filepath}")

            for i, row in enumerate(reader):
                if not row:  # Skip empty rows
                    print(f"Skipping empty row {i+1}.")
                    continue
                
                domain_name = row[0].strip().lower() # Assuming domain is in the first column
                
                if not domain_name:
                    print(f"Skipping empty domain name in row {i+1}.")
                    writer.writerow(["EMPTY_ROW", "No domain provided in this row."])
                    continue

                # Basic validation (can be improved)
                if '.' not in domain_name or ' ' in domain_name or len(domain_name) > 253:
                    print(f"Skipping invalid domain format in row {i+1}: '{domain_name}'")
                    writer.writerow([domain_name, "Invalid domain format"])
                    continue
                
                print(f"Processing ({i+1}): {domain_name}...")
                
                try:
                    domain_information = get_domain_info(domain_name)
                    writer.writerow([domain_name, domain_information])
                    print(f"Finished: {domain_name}")
                except Exception as e:
                    # This is a catch-all for unexpected errors during get_domain_info call itself
                    print(f"Critical error processing {domain_name}: {e}")
                    writer.writerow([domain_name, f"Critical error during processing for {domain_name}: {e}"])
                
                # Be respectful to servers: add a delay
                # Adjust sleep time as needed. 0.5 to 1 second is usually a good start.
                time.sleep(0.75) 

            print("\nProcessing complete.")

    except FileNotFoundError:
        print(f"Error: Input file '{input_filepath}' not found.")
    except Exception as e:
        print(f"An unexpected error occurred during file processing: {e}")

if __name__ == "__main__":
    input_csv = input("Enter the path to your input CSV file (e.g., domains.csv): ")
    output_csv = input("Enter the desired path for your output CSV file (e.g., domain_details.csv): ")

    process_csv_files(input_csv, output_csv)

    print(f"""
    --------------------------------------------------------------------
    Script finished.
    Please check '{output_csv}' for the results.

    Important Notes:
    1. WHOIS Data Consistency: The structure and availability of WHOIS data can vary greatly
       between domain registrars and TLDs. Some information might be marked 'N/A' if it's
       not provided, not parsed by the library, or hidden due to privacy services.
    2. Privacy Services: Many domains use privacy services (like "Domains By Proxy"),
       which will mask the actual registrant's contact details. The script reports what is publicly available.
    3. Detailed Contact Info: The `python-whois` library may not always parse detailed street
       addresses for contacts into separate fields. The script retrieves common attributes.
       Your example output for lvt.com is quite detailed, likely due to a specific registrar's
       WHOIS format; universal parsing of such detail is complex.
    4. Rate Limiting: Performing many queries quickly can lead to temporary blocks by
       WHOIS or DNS servers. The script includes a small delay. If you process many domains,
       you might need to increase this delay or handle rate-limiting errors more robustly.
    5. Library Installation: Ensure you have installed the required libraries:
       `pip install python-whois dnspython`
    --------------------------------------------------------------------
    """)