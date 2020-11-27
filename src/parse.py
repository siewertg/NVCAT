import paramiko
import re

def span(sections):
    regex = {"interface": re.compile("^interface (.+)\n"),
             "ipv4_addr": re.compile("address ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"),
             "ipv6_addr": re.compile("address ([0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+::[0-9a-f]+/64)"),
             "dest": re.compile("destination ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"),
             "monitor_dest": re.compile("monitor session (.+) destination (.+)\n"),
             "monitor_src": re.compile("monitor session (.+) source (.+)\n"),
             "vlan_access": re.compile("switchport access (.+)\n")}
    results = {"Interface Name": [], "IP Address": [], "Found": [], "Missing": [],
            "Source": None, "Destination": None, "Shutdown": [], "Error": []}
    span_count = 0
    interface_count = 0
    for section in sections:
        regex_span_src = regex["monitor_src"].search(section)
        regex_span_dest = regex["monitor_dest"].search(section)
        if regex_span_src:
            results["Source"] = regex_span_src.group(2)
        if regex_span_src:
            results["Destination"] = regex_span_dest.group(2)

    src = results["Source"]
    remote_src = False
    vlan_src = False
    int_src = False
    if src and "remote " in src:
        src = src[len("remote "):]
        remote_src = True
    if src and "vlan " in src:
        vlan_src = True
    if src and "interface " in src:
        src = src[len("interface "):]
        int_src = True

    for section in sections:
        regex_int = regex["interface"].search(section)
        regex_ipv4 = regex["ipv4_addr"].search(section)
        regex_ipv6 = regex["ipv6_addr"].search(section)
        regex_vlan_access = regex["vlan_access"].search(section)
        if regex_int:
            interface_count += 1
            results["Interface Name"].append(regex_int.group(1))
            results["Shutdown"].append(False)
            for line in section.split('\n'):
                if line.strip() == "shutdown":
                    results["Shutdown"][-1] = True

            ip_addr = []
            if regex_ipv4:
                ip_addr.append(regex_ipv4.group(1)+" (IPv4)")
            if regex_ipv6:
                ip_addr.append(regex_ipv6.group(1)+" (IPv6)")

            if (regex_vlan_access and vlan_src and
                regex_vlan_access.group(1) == src) or (int_src and
                results["Interface Name"][-1] == src):
                results["Found"].append("SPAN")
                results["Missing"].append(None)
            else:
                results["Found"].append(None)
                results["Missing"].append("SPAN")

            if len(ip_addr) == 2:
                ip_addr = ip_addr[0]+"; "+ip_addr[1]
            elif len(ip_addr) == 1:
                ip_addr = ip_addr[0]
            else:
                ip_addr = None
            results["IP Address"].append(ip_addr)

    if not results["Source"]:
        results["Error"].append("No Source")
    if not results["Destination"]:
        results["Error"].append("No Destination")
    elif "interface " in results["Destination"]:
        results["Destination"] = results["Destination"][len("interface "):]
        for interface in results["Interface Name"]:
            if results["Destination"] == interface or \
              (results["Destination"][:2] == interface[:2] and results["Destination"][2:] in interface):
                results["Destination"] = interface

    for i in range(0, len(results["Interface Name"])):
        if results["Interface Name"][i] == results["Destination"]:
            if results["Shutdown"][i]:
                results["Error"].append("Destination Shutdown")

    for cell in results["Missing"]:
        if not cell:
            span_count += 1

    if results["Error"]:
        span_count = 0
        for i in range(0, len(results["Missing"])):
            if results["Found"][i] == "SPAN":
                results["Missing"][i] = "SPAN"
                results["Found"][i] = None

    results["Score"] = (span_count, interface_count)
    if remote_src:
        results["Score"] = "Undefined"

    return results

def netflow(sections):
    regex = {"interface": re.compile("^interface (.+)\n"),
             "ipv4_addr": re.compile("address ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"),
             "ipv6_addr": re.compile("address ([0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+::[0-9a-f]+/64)"),
             "flow_exp": re.compile("flow (exporter|exporter-map) (.+)"),
             "flow_ipv4": re.compile("flow ipv4 monitor (.*)\n"),
             "flow_ipv6": re.compile("flow ipv6 monitor (.*)\n"),
             "dest": re.compile("destination ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"),
             "monitor_dest": re.compile("monitor session (.+) source (.+)\n"),
             "monitor_src": re.compile("monitor session (.+) source (.+)\n")}

    interface_count = 0
    netflow_count = 0
    flow_exp = []
    results = {"Interface Name": [], "IP Address": [], "Found": [], "Missing": []}
    for section in sections:
        regex_int = regex["interface"].search(section)
        regex_flow_exp = regex["flow_exp"].search(section)
        regex_monitor_dest = regex["monitor_dest"].search(section)
        regex_monitor_src = regex["monitor_src"].search(section)

        if regex_int:
            regex_ipv4 = regex["ipv4_addr"].search(section)
            regex_ipv6 = regex["ipv6_addr"].search(section)
            regex_flow_ipv4 = regex["flow_ipv4"].search(section)
            regex_flow_ipv6 = regex["flow_ipv6"].search(section)

            results["Interface Name"].append(regex_int.group(1))
            if regex_ipv4 or regex_ipv6:
                interface_count += 1

            ip_addr = []
            flow_found = []
            flow_missing = []
            if regex_ipv4:
                ip_addr.append(regex_ipv4.group(1)+" (IPv4)")
                if regex_flow_ipv4 and flow_exp:
                    flow_found.append("NetFlow (IPv4)")
                else:
                    flow_missing.append("NetFlow (IPv4)")
            if regex_ipv6:
                ip_addr.append(regex_ipv6.group(1)+" (IPv6)")
                if regex_flow_ipv6 and flow_exp:
                    flow_found.append("NetFlow (IPv6)")
                else:
                    flow_missing.append("NetFlow (IPv6)")

            if len(flow_found) == 2:
                flow_found = flow_found[0]+"; "+flow_found[1]
            elif len(flow_found) == 1:
                flow_found = flow_found[0]
            else:
                flow_found = None
            results["Found"].append(flow_found)

            if len(flow_missing) == 2:
                flow_missing = flow_missing[0]+"; "+flow_missing[1]
            elif len(flow_missing) == 1:
                flow_missing = flow_missing[0]
            else:
                flow_missing = None
            results["Missing"].append(flow_missing)

            if len(ip_addr) == 2:
                ip_addr = ip_addr[0]+"; "+ip_addr[1]
            elif len(ip_addr) == 1:
                ip_addr = ip_addr[0]
            else:
                ip_addr = None
            results["IP Address"].append(ip_addr)

        if regex_flow_exp:
            regex_dest = regex["dest"].search(section)
            if regex_dest:
                flow_exp.append((regex_flow_exp.group(2), regex_dest.group(1)))

    # For NetFlow, we only care about interfaces with IP addresses
    for i in range(len(results["IP Address"]) - 1, -1, -1):
        if not results["IP Address"][i]:
            del results["Interface Name"][i]
            del results["IP Address"][i]
            del results["Found"][i]
            del results["Missing"][i]

    for cell in results["Missing"]:
        if not cell:
            netflow_count += 1

    results["Flow Exporter"] = True if flow_exp else False
    if not results["Flow Exporter"]:
        netflow_count = 0
        for i in range(0, len(results["Missing"])):
            if results["Found"][i]:
                results["Missing"][i].append(results["Found"][i])
                results["Found"][i] = None
    results["Score"] = (netflow_count, interface_count)
    return results

def http(sections):
    regex = {"http": re.compile("^http server enable")}
    results = {"HTTP Enabled?": ["No"]}
    for section in sections:
        if regex["http"].search(section):
            results["HTTP Enabled?"] = ["Yes"]
            results["Score"] = "Fail"
            return results
    results["Score"] = "Pass"
    return results

def acl(lines):
    regex = {"permit_ip": re.compile("access-list (.*) permit ip"),
            "permit_tcp_any": re.compile("access-list (.*) permit tcp any"),
            "permit_udp_any": re.compile("access-list (.*) permit udp any"),
            "telnet": re.compile("access-list (.*) permit (.*) eq (telnet|23)"),
            "tftp": re.compile("access-list (.*) permit (.*) eq (tftp|69)"),
            "ftp": re.compile("access-list (.*) permit (.*) eq (ftp|20|21)"),
            "loc-srv": re.compile("access-list (.*) permit (.*) eq (loc-srv|135)"),
            "profile": re.compile("access-list (.*) permit (.*) eq (profile|136)"),
            "netbios-ns": re.compile("access-list (.*) permit (.*) eq (netbios-ns|137)"),
            "netbios-dgm": re.compile("access-list (.*) permit (.*) eq (netbios-dgm|138)"),
            "netbios-ss": re.compile("access-list (.*) permit (.*) eq (netbios-ss|139)")}

    results = { "Line": [], "Entry": [] }

    for i in range(0, len(lines)):
        if (regex["permit_ip"].search(lines[i]) or
            regex["permit_tcp_any"].search(lines[i]) or
            regex["permit_udp_any"].search(lines[i]) or
            regex["telnet"].search(lines[i]) or
            regex["tftp"].search(lines[i]) or
            regex["ftp"].search(lines[i]) or
            regex["loc-srv"].search(lines[i]) or
            regex["profile"].search(lines[i]) or
            regex["netbios-ns"].search(lines[i]) or
            regex["netbios-dgm"].search(lines[i]) or
            regex["netbios-ss"].search(lines[i])):
            results["Line"].append(str(i+1))
            results["Entry"].append(lines[i].strip().strip('\n'))
        if results["Entry"]:
            while not all(len(s) <= 100 for s in results["Entry"][-1].split('\n')):
                results["Entry"][-1] = fix_width(results["Entry"][-1], 100)
        
    if not results["Entry"]:
        results["Score"] = "Pass"
    else:
        results["Score"] = "Fail"

    return results

def fix_width(s, max_len):
    l = s.split('\n')
    if len(l[-1]) > max_len:
        i = max_len
        for i in range(max_len, 0, -1):
            if l[-1][i] == ' ':
                break
        l[-1] = l[-1][:i]+'\n'+l[-1][-len(l[-1])+i:]
    return '\n'.join(l)

def get_sections(lines):
    regex = {"section": re.compile("^!(.*)\n")}
    sections = []
    sec_nums = []
    i = 0
    for line in lines:
        regex_section = regex["section"].search(line)
        if regex_section:
            sec_nums.append(i)
        i += 1
    i = 0
    for j in range(0, len(sec_nums)):
        sections.append("".join(lines[i:sec_nums[j]]))
        i = sec_nums[j] + 1
    sections.append("".join(lines[i:]))
    return sections

def get_sections_local(specs):
    with open(specs["config"], 'r') as f:
        lines = f.readlines()
        if specs["search"] == ["ACL Values"]:
            return lines
        return get_sections(lines)

def get_sections_remote(specs):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if specs["authentication"] == "password":
        client.connect(hostname=specs["ip_address"],
                       username=specs["username"],
                       password=specs["password"],
                       allow_agent=False,
                       look_for_keys=False)
    else:
        key = paramiko.RSAKey.from_private_key_file(specs["ssh_key_file"])
        client.connect(hostname=specs["ip_address"], pkey=key)
    cmd = "show running-config"
    if "ACL Values" in specs["search"]:
        cmd = "show access-list"
    stdin, stdout, stderr = client.exec_command(cmd)
    config = stdout.read().decode("utf-8")
    if "ACL Values" in specs["search"]:
        return config.split('\n')
    return get_sections(config.split('\n'))

def get_results(item, sections):
    if item == "ACL Values":
        return acl(sections)
    if item == "NetFlow":
        return netflow(sections)
    if item == "SPAN":
        return span(sections)
    if item == "HTTP":
        return http(sections)

def parse_config(specs):
    if specs["local"]:
        sections = get_sections_local(specs)
    else:
        sections = get_sections_remote(specs)

    results = {}
    for item in specs["search"]:
        results[item] = get_results(item, sections)

    return results

