def parse_firewall_logs(log_file):
    # Open the specified file which stored log details in read mode.
    with open(log_file, 'r') as file:
        # Read all lines from the file and store them in the 'logs' list.
        logs = file.readlines()

    # Create an empty list to store parsed log entries.
    parsed_logs = []

    # Iterate through each log entry in the 'logs' list.
    for log in logs:
        # Skip lines that start with '#' as they are considered comments.
        if log.startswith('#'):
            continue

        # Split the log entry into parts using whitespace as the separator.
        parts = log.split()

        # Check if the log entry contains at least 11 parts.
        if len(parts) >= 11:
            # Extract specific information from the log entry and store it in a dictionary.
            date, time, action, protocol, src_ip, dst_ip, src_port, dst_port, size, tcp_flags, info = parts[:11]
            parsed_logs.append({
                'date': date,
                'time': time,
                'action': action,
                'protocol': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'size': size,
                'tcp_flags': tcp_flags,
                'info': ' '.join(parts[11:])
            })

    # Return the list of parsed log entries.
    return parsed_logs

def analyze_firewall_logs(parsed_logs):
    # Create an empty list to store potential threats.
    potential_threats = []

    # Iterate through each parsed log entry.
    for log in parsed_logs:
        # Check if the 'action' field in the log entry is 'BLOCK', indicating a blocked traffic entry.
        if log['action'] == 'BLOCK':
            potential_threats.append(log)

    # Return the list of potential threats.
    return potential_threats

def generate_summary_report(potential_threats):
    # Initialize the summary report with a header.
    summary_report = " -------------------------------\n| Firewall Log Analysis Summary |\n -------------------------------\n\n"

    # Check if there are potential threats in the list.
    if len(potential_threats) > 0:
        summary_report += "Potential Threats:\n"
        # Iterate through potential threats and include relevant information in the summary.
        for threat in potential_threats:
            summary_report += f"Date: {threat['date']}, Time: {threat['time']}, Source IP: {threat['src_ip']}, Destination IP: {threat['dst_ip']}, Action: {threat['action']}, Info: {threat['info']}\n"
    else:
        # If no potential threats were found, indicate that in the summary.
        summary_report += "No potential threats identified in the log files.\n"

    return summary_report

if __name__ == "__main__":
    # Specify the log file.
    log_file = "firewall_log.txt"

    # Parse the firewall logs from the log file and store them in 'parsed_logs'.
    parsed_logs = parse_firewall_logs(log_file)

    # Analyze the parsed logs and identify potential threats, storing them in 'potential_threats'.
    potential_threats = analyze_firewall_logs(parsed_logs)

    # Generate a summary report based on the potential threats.
    summary_report = generate_summary_report(potential_threats)

    # Print log summary report
    print(summary_report)