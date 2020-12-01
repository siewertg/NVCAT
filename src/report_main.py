import os
from datetime import datetime
from tkinter import *
from tkinter import filedialog
from tkinter.messagebox import showinfo
from tkinter.simpledialog import askstring

from tabulate import tabulate
from parse import *
from report_rw import *

TABLE_FMT = "pretty"
KNOWN_HOSTS_FILE = "~/.ssh/known_hosts"

NO_NETFLOW_TEXT = "No NetFlow exporters are enabled."
SPAN_ERROR_TEXT = {"No Source": "No SPAN traffic source specified.",
                   "No Destination": "No SPAN traffic destination specified.",
                   "Destination Shutdown": "SPAN traffic destination is shut down."}

# Return list of files in directory
def get_files(directory):
    try:
        files = os.listdir(directory)
    except Exception:
        return None

    # Remove hidden files
    for filename in files:
        if filename[0] == '.':
            files.remove(filename)
    return files

# Call appropriate report generation function
def report_generation(specs):
    if specs["batch"]:
        batch(specs)
    else:
        individual(specs)

# Perform batch analysis
def batch(specs):
    config_folder = specs["config"]
    report_folder = specs["report"]
    specs["Score"] = {}
    specs["Totals"] = {}
    for item in specs["search"]:
        specs["Totals"][item] = None
    for config in sorted(get_files(config_folder)):
        specs["config"] = config_folder+'/'+config
        config, ext = os.path.splitext(config)
        specs["report"] = os.path.join(report_folder, '')+config.split('/')[-1]+"_report"+ext
        individual(specs)
        for item in specs["Totals"]:
            if not specs["Totals"][item]:
                specs["Totals"][item] = [[specs["Score"][item], config]]
            else:
                specs["Totals"][item].append([specs["Score"][item], config])
    generate_aggregate(specs, config_folder, report_folder)

# Return text of report header
def report_header(specs, config_folder):
    time_format = "%Y-%m-%d %H:%M:%S"
    if config_folder:
        title = "Network Visibility Aggregate Report\n===================================\n"
    else:
        title = "Network Visibility Report\n=========================\n"
    header = (title+
                "\nDate Generated: "+str(datetime.utcnow().strftime(time_format)+" UTC")+
                "\nDevice: ".ljust(17)+specs["type"]+
                "\nPlatform: ".ljust(17)+specs["platform"]+
                "\nLooking For: ".ljust(17)+", ".join(specs["search"]))
    if specs["local"]:
        if specs["batch"] and config_folder:
            header += "\nConfig Folder: ".ljust(17)+config_folder
        else:
            header += "\nConfig File: ".ljust(17)+specs["config"]
    else:
        auth_type = "Password" if specs["authentication"] == "password" else "SSH Key"
        header += "\nAuthentication: "+auth_type
    return header

# Generate aggregate summary report
def generate_aggregate(specs, config_folder, report_folder):
    aggregate_filename = os.path.join(report_folder, '')+\
                         config_folder.split('/')[-1]+"-summary.txt"
    reportText = report_header(specs, config_folder)
    resultText = ""
    results_csv = ""
    total = {}
    num_files = len(get_files(config_folder))
    for item in specs["search"]:
        total[item] = None
        if len(specs["search"]) > 1:
            resultText += (item+": Aggregate Summary\n"+
                           '='*len(item+": Aggregate Summary")+'\n')
        results = {}
        results["Config File"] = []
        results["Score"] = []
        for score, config in specs["Totals"][item]:
            results["Config File"].append(config)
            if not total[item]:
                if type(score) is tuple:
                    total[item] = list(score)
                else:
                    total[item] = list((score, num_files))
            elif type(score) is tuple:
                total[item][0] += score[0]
                total[item][1] += score[1]
            else:
                total[item][0] += score
            if type(score) is int:
                score = "Pass" if score == 1 else "Fail"
            if type(score) is tuple:
                if score[1] == 0:
                    score = (str(score[0])+'/'+str(score[1])+" (0.00%)")
                else:
                    score = (str(score[0])+'/'+str(score[1])+" ("+
                            str(round((score[0] / score[1]) * 100, 2))+"%)")
            results["Score"].append(score)
        resultText += "Aggregate Score: "
        resultText += (str(total[item][0])+'/'+str(total[item][1])+" ("+
                       str(round((total[item][0] / total[item][1]) * 100, 2))+"%)\n")
        resultText += (tabulate(results, headers="keys", tablefmt=TABLE_FMT)+'\n\n\n')
        results_csv += get_csv(results)+"\n\n"

    reportText += "\n\n"+resultText
    write_report(config_folder, aggregate_filename, reportText, results_csv, specs["passwd"])

# Perform individual analysis
def individual(specs):
    reportText = report_header(specs, None)
    results = parse_config(specs)
    if not specs["local"] and specs["authentication"] == "ssh_key":
        remove_known_host(specs)
    resultText = ""
    rubric = {100: "Excellent",
              90: "Excellent",
              80: "Good",
              70: "Fair",
              60: "Poor",
               0: "Unsatisfactory"}
    if not specs["batch"]:
        specs["Score"] = {}
    if "NetFlow" in results:
        netflow_results = results["NetFlow"]
        if len(results.keys()) > 1:
            resultText += "NetFlow: Summary\n================\n\n"
        if "Flow Exporter" in netflow_results and not netflow_results["Flow Exporter"]:
            resultText += NO_NETFLOW_TEXT+'\n'
        if "Score" in netflow_results:
            specs["Score"]["NetFlow"] = netflow_results["Score"]
            if netflow_results["Score"][1] == 0:
                netflow_results["Score"] = 0
            else:
                netflow_results["Score"] = round((netflow_results["Score"][0] \
                                                / netflow_results["Score"][1]) * 100, 2)
            resultText += "Suggested Score: "+str(netflow_results["Score"])+"% ("
            if netflow_results["Score"] // 10 * 10 in rubric:
                scoreText = rubric[netflow_results["Score"] // 10 * 10]
            else:
                scoreText = rubric[0]
            resultText += scoreText+")\n"
        netflow_results.pop("Flow Exporter", None)
        netflow_results.pop("Score", None)
        resultText += (tabulate(netflow_results, headers="keys", tablefmt=TABLE_FMT)+
                       "\n\n\n")
    if "SPAN" in results:
        span_results = results["SPAN"]
        if len(results.keys()) > 1:
            resultText += "SPAN: Summary\n=============\n\n"
        if "Error" in span_results:
            for err in span_results["Error"]:
                resultText += SPAN_ERROR_TEXT[err]+'\n'
        if "Score" in span_results:
            specs["Score"]["SPAN"] = span_results["Score"]
            if span_results["Score"] != "Undefined":
                if span_results["Score"][1] == 0:
                    span_results["Score"] = 0
                else:
                    span_results["Score"] = round((span_results["Score"][0] \
                                                   / span_results["Score"][1]) * 100, 2)
                scoreText = str(span_results["Score"])+"% ("
                if span_results["Score"] // 10 * 10 in rubric:
                    scoreText += rubric[span_results["Score"] // 10 * 10]+')'
                else:
                    scoreText += rubric[0]+")\n"
            else:
                scoreText = (span_results["Score"]+
                            " (Remote Source; Additional Context Needed)")
                specs["Score"]["SPAN"] = (0, 0)
            resultText += "Suggested Score: "+scoreText+'\n'
        resultText += "Source: ".ljust(17)
        if not span_results["Source"]:
            span_results["Source"] = "None"
        resultText += span_results["Source"]+'\n'
        resultText += "Destination: ".ljust(17)
        if not span_results["Destination"]:
            span_results["Destination"] = "None"
        resultText += span_results["Destination"]+'\n'
        for col in ["Score", "Error", "Shutdown", "Source", "Destination"]:
            span_results.pop(col, None)
        resultText += (tabulate(span_results, headers="keys", tablefmt=TABLE_FMT)+"\n\n\n")
    if "HTTP" in results:
        http_results = results["HTTP"]
        if len(results.keys()) > 1:
            resultText += "HTTP: Summary\n=============\n\n"
        specs["Score"]["HTTP"] = 1 if http_results["Score"] == "Pass" else 0
        resultText += "Suggested Score: "+http_results["Score"]+'\n'
        http_results.pop("Score", None)
        resultText += (tabulate(http_results, headers="keys", tablefmt=TABLE_FMT)+'\n\n\n')
    if "ACL Entries" in results:
        acl_results = results["ACL Entries"]
        if len(results.keys()) > 1:
            resultText += "ACL Entries: Summary\n===================\n\n"
        specs["Score"]["ACL Entries"] = 1 if acl_results["Score"] == "Pass" else 0
        resultText += "Suggested Score: "+acl_results["Score"]+'\n'
        acl_results.pop("Score", None)
        resultText += (tabulate(acl_results, headers="keys", tablefmt=TABLE_FMT)+'\n\n\n')

    reportText += "\n\n"+resultText
    results_csv = ""
    for item in results:
        results_csv += get_csv(results[item])+"\n\n"
    write_report(specs["config"], specs["report"], reportText, results_csv, specs["passwd"])

# Return CSV-formatted report
def get_csv(results):
    results_csv = ','.join(results.keys())+'\n'
    for key in results:
        for i in range(0, len(results[key])):
            if not results[key][i]:
                results[key][i] = ""
    rows = [','.join(i) for i in list(zip(*[results[key] for key in results.keys()]))]
    for row in rows:
        results_csv += row.strip(',')+'\n'
    results_csv = results_csv[:-1]
    return results_csv

# Remove entry from SSH known_hosts file if needed
def remove_known_host(specs):
    try:
        with open(KNOWN_HOSTS_FILE, 'r') as f:
            lines = f.readlines()
        with open(KNOWN_HOSTS_FILE, 'w') as f:
            for line in lines:
                if specs["ip_address"] not in line:
                    f.write(line)
    except Exception:
        showinfo("Error", "Could not remove IP address "+specs["ip_address"]+" from list of known hosts.")

