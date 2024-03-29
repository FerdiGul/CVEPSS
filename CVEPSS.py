import requests
import sys
import time
import re
import textwrap
import nvdlib
from epss_api import EPSS
import argparse
from tabulate import tabulate
 
def cve_cpeValues(cpe):
    try:
        padding=76
        print("\n" + "─"*((padding//2)-2)+"CPE"+"─"*((padding//2)-1))
                 
        if cpe is not None and len(cpe) > 0:
            for cpe_value in cpe:
                print(cpe_value)
        else:
            print("\nCPE Not Fount")
            
        print("─"*padding)
        
    except Exception as e:
        print(f"Error retrieving CPE Value: {e}")
        return None

def cve_references(references):
    try:
        padding=33
        matches = re.findall(r"'url': '([^']+)'", str(references))
        print("\n" + "─"*padding+"References"+"─"*padding)
        if matches:
            for match in matches:
                print(match)
        else:
            print("\nReferences Not Fount")
        print("─"*(2*padding)+"─"*10)
    
    except Exception as e:
        print(f"Error retrieving Reference Value: {e}")
        return None
    
def cve_description(description):
    try:
        padding=33
        print("\n" + "─"*padding+"Description"+"─"*padding)
        #if description is not None:
        if description is not None:
            wrapped_description = textwrap.fill(description, width=80)
            print(wrapped_description)
        else:
            print("\nDescription Not Found ")
        print("─"*(2*padding)+"─"*10)
    
    except Exception as e:
        print(f"Error retrieving Description: {e}")
        return None  
    
def cve_output(cve_data,epss,percentile):
    if cve_data is not None:
        headers = [
            "Property",
            "Value"
        ]
        data = [
            ["CVSS Score", cve_data[0]],
            ["EPSS Score (%)", epss],
            ["POV", percentile],
            ["Severity", cve_data[1]],
            ["Published", cve_data[2]],
            ["Last Modified", cve_data[3]],
            ["Exploitability", cve_data[4]],
            ["Impact Score", cve_data[5]],
            ["Attack Vector", cve_data[6]],
            ["Confidentiality Impact", cve_data[7]],
            ["Integrity Impact", cve_data[8]],
            ["Availability Impact",cve_data[9]],
            ["URL", cve_data[10]]   
        ]
        print("\n")
        print(tabulate(data, headers=headers, tablefmt="pretty", showindex=False, numalign="right", stralign="right", colalign=("left", "left")))
        print("\n")
        
        cve_description(cve_data[13])
        cve_references(cve_data[11])
        cve_cpeValues(cve_data[12])

def loading_data(cveID):
    while True:
        for i in range(1, 6):
            sys.stdout.write("\r" + f"Loading {cveID} details" + "." * i + " " * (5 - i))
            sys.stdout.flush()
            time.sleep(0.20)
        try:
            cve_data = nvdlib.searchCVE(cveId=cve_id)[0]
            break  # Break the loop if data is successfully retrieved
        except Exception as e:
            pass

    return cve_data
    
def get_cve_data(cve_id):
    try:
        cve_data = loading_data(cve_id)
        cve_v31score = getattr(cve_data, 'v31score', None)
        cve_v31severity = getattr(cve_data, 'v31severity', None)
        cve_published = getattr(cve_data, 'published', None)
        cve_lastModified = getattr(cve_data, 'lastModified', None)
        cve_v31exploitability = getattr(cve_data, 'v31exploitability', None)
        cve_v31impactScore = getattr(cve_data, 'v31impactScore', None)
        cve_v31attackVector = getattr(cve_data, 'v31attackVector', None)
        cve_v31confidentialityImpact = getattr(cve_data, 'v31confidentialityImpact', None)
        cve_v31integrityImpact = getattr(cve_data, 'v31integrityImpact', None)
        cve_v31availabilityImpact = getattr(cve_data, 'v31availabilityImpact', None)
        cve_url = getattr(cve_data, 'url', 'URL not Found')
        cve_references = getattr(cve_data, 'references', None)
        cve_description = getattr(cve_data.descriptions[0], 'value', None) if hasattr(cve_data, 'descriptions') else None
        cpe_value = getattr(cve_data, 'cpe', None)

        return [
            cve_v31score,
            cve_v31severity,
            cve_published,
            cve_lastModified,
            cve_v31exploitability,
            cve_v31impactScore,
            cve_v31attackVector,
            cve_v31confidentialityImpact,
            cve_v31integrityImpact,
            cve_v31availabilityImpact,
            cve_url,
            cve_references,
            cpe_value,
            cve_description,
        ]
    except Exception as e:
        print(f"Error retrieving CVE Details: {e}")
        return None

def get_epss_score(cveId):
    client = EPSS()
    try:
        epss_score = client.epss(cve_id=cveId)

        if epss_score is not None:
            epssScore = f"{epss_score*100:.3f}"
            percentile_score = client.percentile(cve_id=cveId)
     
            if percentile_score is not None:
                intPercentile = int(percentile_score * 100)
                percentileScore = f"~{intPercentile}% (the Proportion of Vulnerabilities that are scored at or less)"
            else:
                percentileScore = "Not Found"
        else:
            epssScore = "Not Found"
            percentileScore = "Not Found"
            
        return epssScore, percentileScore

    except Exception as e:
        print(f"Error retrieving EPSS score: {e}")
        return None, None

def load():
    print("""\n\t\tWritten by Ferdi Gül @2024\n\t ▁ ▂ ▄ ▅ ▆ ▇ █ CVEPSS v1.0 █ ▇ ▆ ▅ ▄ ▂ ▁\n""")
    parser = argparse.ArgumentParser(description="The CVEPSS v1.0 calculates EPSS and CVSS scores and retrieves CVE details for a vulnerability identified by a given CVE ID")
    parser.add_argument("--id", required=True, help="Usage: python3 CVEPSS.py --id CVE-2023-XXXXX (CVE ID to analyze)")
    args = parser.parse_args()
    return args
    
if __name__ == "__main__":
    args = load()
    cve_id = args.id
    epss,percentile = get_epss_score(cve_id)
    cve_data = get_cve_data(cve_id)
    cve_output(cve_data,epss,percentile)


