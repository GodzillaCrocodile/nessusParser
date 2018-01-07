# EStroev
from xml.etree import ElementTree as etree
import argparse
from datetime import datetime
import os
import csv


def csv_writer(outPathFile, data):
    with open(outPathFile, 'a', newline='') as csv_out:
        csv_out_writer = csv.writer(csv_out, delimiter=';')
        tmlList = list()
        for id in data:
            if [data[id]['ip'], data[id]['cve']] not in tmlList:
                tmlList.append([data[id]['ip'], data[id]['cve']])
        print(f'Len before: {len(data)}')
        print(f'Len after: {len(tmlList)}')
        for item in tmlList:
            csv_out_writer.writerow(
                [
                    item[0],
                    item[1]
                ]
            )
        print(f'[+] Write {len(data)} entries to {outPathFile}')


def critical_vulnerabilities(vulns_dict):
    vulnerabilitiesWithExploit = dict()
    for vulner_id in vulns_dict:
        if "riskFactor" in vulns_dict[vulner_id].keys() and \
                        "cvss_vector" in vulns_dict[vulner_id].keys() \
                and "exploit_available" in vulns_dict[vulner_id].keys():
            if vulns_dict[vulner_id]["riskFactor"] == "Critical" \
                    and vulns_dict[vulner_id]["exploit_available"] == "true":
                vulnerabilitiesWithExploit[vulner_id] = {
                    'pluginName': vulns_dict[vulner_id]["plugin_name"],
                    'port': vulns_dict[vulner_id]["port"],
                    'riskFactor': vulns_dict[vulner_id]["riskFactor"],
                }
    return vulnerabilitiesWithExploit


def cve_vulnerabilities(vulns_dict):
    vulnerabilitiesWithCVE = dict()
    for vulner_id in vulns_dict:
        cvssScrore, cvssVector = '', ''
        if 'cve' in vulns_dict[vulner_id].keys():
            if vulns_dict[vulner_id].get("cvss3_base_score"):
                cvssScrore = vulns_dict[vulner_id]["cvss3_base_score"]
            elif vulns_dict[vulner_id].get("cvss_base_score"):
                cvssScrore = vulns_dict[vulner_id]["cvss_base_score"]
            if vulns_dict[vulner_id].get("cvss3_vector"):
                cvssVector = vulns_dict[vulner_id]["cvss3_vector"]
            elif vulns_dict[vulner_id].get("cvss_vector"):
                cvssVector = vulns_dict[vulner_id]["cvss_vector"]

            cve = next(iter(vulns_dict[vulner_id]["cve"]))
            vulnerabilitiesWithCVE[vulner_id] = {
                'cve': cve,
                'cvss_base_score': cvssScrore,
                'cvss_vector': cvssVector,
                'ip': vulns_dict[vulner_id]["host"],
            }
    return vulnerabilitiesWithCVE


def xml_parser(xml_content):
    vulnerabilities = dict()
    single_params = ["agent", "cvss3_base_score", "cvss3_temporal_score", "cvss3_temporal_vector", "cvss3_vector", "cvss_base_score", "cvss_temporal_score", "cvss_temporal_vector", "cvss_vector", "description", "exploit_available", "exploitability_ease", "exploited_by_nessus", "fname", "in_the_news", "patch_publication_date", "plugin_modification_date", "plugin_name", "plugin_output", "plugin_publication_date", "plugin_type", "script_version", "see_also", "solution", "synopsis", "vuln_publication_date"]
    root = etree.fromstring(xml_content)
    for block in root:
        if block.tag == "Report":
            for report_host in block:
                host_properties_dict = dict()
                for report_item in report_host:
                    if report_item.tag == "HostProperties":
                        for host_properties in report_item:
                            host_properties_dict[host_properties.attrib['name']] = host_properties.text
                for report_item in report_host:
                    if 'pluginName' in report_item.attrib:
                        vulner_id = report_host.attrib['name'] + "|" + report_item.attrib['pluginID'] + "|" + report_item.attrib['port']
                        vulnerabilities[vulner_id] = dict()
                        vulnerabilities[vulner_id]['port'] =  report_item.attrib['port']
                        vulnerabilities[vulner_id]['pluginName'] =  report_item.attrib['pluginName']
                        vulnerabilities[vulner_id]['pluginFamily'] =  report_item.attrib['pluginFamily']
                        vulnerabilities[vulner_id]['pluginID'] =  report_item.attrib['pluginID']
                        for param in report_item:
                            if param.tag == "risk_factor":
                                risk_factor = param.text
                                vulnerabilities[vulner_id]['host'] = report_host.attrib['name']
                                vulnerabilities[vulner_id]['riskFactor'] = risk_factor
                            else:
                                if not param.tag in single_params:
                                    if not param.tag in vulnerabilities[vulner_id]:
                                        vulnerabilities[vulner_id][param.tag] = set()
                                    vulnerabilities[vulner_id][param.tag].add(param.text)
                                else:
                                    vulnerabilities[vulner_id][param.tag] = param.text
                        for param in host_properties_dict:
                            vulnerabilities[vulner_id][param] = host_properties_dict[param]
    return vulnerabilities


def main():
    parser = argparse.ArgumentParser(description='Nessus report parser')
    parser.add_argument('-f', dest='inFile', action='store', help='Input file with Nessus report')
    parser.add_argument('-o', dest='outFolder', action='store', help='Output folder')

    args = parser.parse_args()

    if not args.inFile:
        print('[-] You must specify an existing input path!')
        exit(-1)
    elif not os.path.exists(args.inFile):
        print('[-] Input path %s does not exist!' % os.path.abspath(args.inFile))
        exit(-1)
    if not args.outFolder:
        print('[-] You must specify an existing path to the output folder!')
        exit(-1)
    elif not os.path.exists(args.outFolder):
        print(f'[-] Output folder {os.path.abspath(args.outFolder)} does not exist!')
        os.makedirs(args.outFolder)
        print(f'[+] Create output folder {args.outFolder}')
    elif not os.path.exists(args.outFolder):
        print(f'[-] Output folder {outFolder} does not exist!')
        os.makedirs(args.outFolder)
        print(f'[+] Create output folder {outFolder}')

    outFileName = os.path.basename(args.inFile)
    outFile = os.path.join(args.outFolder, f'{outFileName}_parse.csv')

    if os.path.exists(outFile):
        os.remove(outFile)
        print(f'[-] Output file {outFile} exist! Removed it!')

    startTime = datetime.now()
    print(startTime.strftime('[*] Start time: %d.%m.%Y %H:%M:%S'))

    with open(args.inFile, 'r') as inF:
        xmlContent = inF.read()
    vulnerabilities = xml_parser(xmlContent)

    # for x in vulnerabilities:
    #     print(x, vulnerabilities[x])

    vulnerabilitiesWithExploit = critical_vulnerabilities(vulnerabilities)
    vulnerabilitiesWithCVE = cve_vulnerabilities(vulnerabilities)
    # for x in vulnerabilitiesWithCVE:
    #     print(vulnerabilities[x])
    csv_writer(outFile, vulnerabilitiesWithCVE)

    endTime = datetime.now()
    print('[*] Total elapsed time - {0} seconds'.format((endTime - startTime).seconds))
    print(endTime.strftime('[*] End time: %d.%m.%Y %H:%M:%S'))

if __name__ == '__main__':
    main()
