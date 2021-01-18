# This file is part of OpenCAVS.

# OpenCAVS is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# OpenCAVS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with OpenCAVS.  
# If not, see https://github.com/jonrau1/CodeArtifactVulnScanner/blob/main/LICENSE.

import sys
import json
import boto3
import re
from decimal import Decimal

cveTable = sys.argv[1]
awsRegion = sys.argv[2]

ddbr = boto3.resource('dynamodb', region_name=awsRegion)
table = ddbr.Table(cveTable)

# Within CPE 2.3 the "a" means Application e.g. Software Package
# We will use this to grab only these and ignore OS and Hardware
cpeAppRegex = re.compile('cpe:2.3.a:')

#2002
print('Parsing NVD CVE 2002 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2002.json') as cve2002json:
    cve2002 = json.load(cve2002json)
    try:
        for x in cve2002['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2002 JSON and sent to DynamoDB!')

#2003
print('Parsing NVD CVE 2003 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2003.json') as cve2003json:
    cve2003 = json.load(cve2003json)
    try:
        for x in cve2003['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2003 JSON and sent to DynamoDB!')

#2004
print('Parsing NVD CVE 2004 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2004.json') as cve2004json:
    cve2004 = json.load(cve2004json)
    try:
        for x in cve2004['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2004 JSON and sent to DynamoDB!')

#2005
print('Parsing NVD CVE 2005 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2005.json') as cve2005json:
    cve2005 = json.load(cve2005json)
    try:
        for x in cve2005['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2005 JSON and sent to DynamoDB!')

#2006
print('Parsing NVD CVE 2006 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2006.json') as cve2006json:
    cve2006 = json.load(cve2006json)
    try:
        for x in cve2006['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2006 JSON and sent to DynamoDB!')

#2007
print('Parsing NVD CVE 2007 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2007.json') as cve2007json:
    cve2007 = json.load(cve2007json)
    try:
        for x in cve2007['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2007 JSON and sent to DynamoDB!')

#2008
print('Parsing NVD CVE 2008 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2008.json') as cve2008json:
    cve2008 = json.load(cve2008json)
    try:
        for x in cve2008['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2008 JSON and sent to DynamoDB!')

#2009
print('Parsing NVD CVE 2009 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2009.json') as cve2009json:
    cve2009 = json.load(cve2009json)
    try:
        for x in cve2009['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2009 JSON and sent to DynamoDB!')

#2010
print('Parsing NVD CVE 2010 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2010.json') as cve2010json:
    cve2010 = json.load(cve2010json)
    try:
        for x in cve2010['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2010 JSON and sent to DynamoDB!')

#2011
print('Parsing NVD CVE 2011 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2011.json') as cve2011json:
    cve2011 = json.load(cve2011json)
    try:
        for x in cve2011['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2011 JSON and sent to DynamoDB!')

#2012
print('Parsing NVD CVE 2012 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2012.json') as cve2012json:
    cve2012 = json.load(cve2012json)
    try:
        for x in cve2012['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2012 JSON and sent to DynamoDB!')

#2013
print('Parsing NVD CVE 2013 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2013.json') as cve2013json:
    cve2013 = json.load(cve2013json)
    try:
        for x in cve2013['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2013 JSON and sent to DynamoDB!')

#2014
print('Parsing NVD CVE 2014 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2014.json') as cve2014json:
    cve2014 = json.load(cve2014json)
    try:
        for x in cve2014['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2014 JSON and sent to DynamoDB!')

#2015
print('Parsing NVD CVE 2015 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2015.json') as cve2015json:
    cve2015 = json.load(cve2015json)
    try:
        for x in cve2015['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2015 JSON and sent to DynamoDB!')

#2016
print('Parsing NVD CVE 2016 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2016.json') as cve2016json:
    cve2016 = json.load(cve2016json)
    try:
        for x in cve2016['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2016 JSON and sent to DynamoDB!')

#2017
print('Parsing NVD CVE 2017 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2017.json') as cve2017json:
    cve2017 = json.load(cve2017json)
    try:
        for x in cve2017['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2017 JSON and sent to DynamoDB!')

#2018
print('Parsing NVD CVE 2018 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2018.json') as cve2018json:
    cve2018 = json.load(cve2018json)
    try:
        for x in cve2018['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2018 JSON and sent to DynamoDB!')

#2019
print('Parsing NVD CVE 2010 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2019.json') as cve2019json:
    cve2019 = json.load(cve2019json)
    try:
        for x in cve2019['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2019 JSON and sent to DynamoDB!')

#2020
print('Parsing NVD CVE 2020 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2020.json') as cve2020json:
    cve2020 = json.load(cve2020json)
    try:
        for x in cve2020['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2020 JSON and sent to DynamoDB!')

#2021
print('Parsing NVD CVE 2021 JSON and sending to DynamoDB')

with open('./nvdcve-1.1-2021.json') as cve2021json:
    cve2021 = json.load(cve2021json)
    try:
        for x in cve2021['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            # We just need to grab the first one - there can be more but whatever
            try:
                cveRef = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                cveRef = 'NONE_PROVIDED'
            try:
                cveDesc = str(x['cve']['description']['description_data'][0]['value'])
            except:
                cveDesc = 'NONE_PROVIDED'
            try:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'CVSSv2.0'
                cvssV2Vector = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = str(x['impact']['baseMetricV3']['cvssV3']['vectorString'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'CVSSv3.0'
                cvssV3Vector = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            # If Nodes list is empty that means it's likely a revoked CVE
            if str(x['configurations']['nodes']) == '[]':
                pass
            else:
                for node in x['configurations']['nodes']:
                    try:
                        for cpe in node['cpe_match']:
                            cpeUri = str(cpe['cpe23Uri'])
                            appCheck = cpeAppRegex.search(cpeUri)
                            if appCheck:
                                # Remove the Regex statement and split the CPE URI - this will
                                # allow us the easily pluck out the Package and Vendor info
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                vendor = stripped[0]
                                packageName = stripped[1] 
                                packageVer = stripped[2]
                                if packageVer == '*':
                                    try:
                                        versionStartIncluding = str(cpe['versionStartIncluding'])
                                    except:
                                        versionStartIncluding = 'NO_START'
                                    try:
                                        versionEndExcluding = str(cpe['versionEndExcluding'])
                                    except:
                                        versionEndExcluding = 'NOT_APPLICABLE'
                                else:
                                    versionStartIncluding = 'NOT_APPLICABLE'
                                    versionEndExcluding = 'NOT_APPLICABLE'

                                table.put_item(
                                    Item={
                                        'PackageName': packageName,
                                        'PackageVersion': packageVer,
                                        'CveId': cveId,
                                        'VersionStartIncluding': versionStartIncluding,
                                        'VersionEndExcluding': versionEndExcluding,
                                        'CveSourceUrl': cveSrcUrl,
                                        'CveDescription': cveDesc,
                                        'Reference': cveRef,
                                        'CvssV2Vector': cvssV2Vector,
                                        'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                        'CvssV2Severity': cvssV2Severity,
                                        'CvssV2Version': cvssV2Version,
                                        'CvssV3Vector': cvssV3Vector,
                                        'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                        'CvssV3Severity': cvssV3Severity,
                                        'CvssV3Version': cvssV3Version,
                                        'Vendor': vendor
                                    }
                                )
                            else:
                                pass
                    # This Except loop will catch CPEs that have another nested list called
                    # children - this happens when there are complex Boolean Types that the CVE
                    # is only present for an AND - we won't actually attempt to parse that logic
                    # TODO: Try to parse "that logic" lol...
                    except:
                        for c in node['children']:
                            for cpe in c['cpe_match']:
                                cpeUri = str(cpe['cpe23Uri'])
                                appCheck = cpeAppRegex.search(cpeUri)
                                if appCheck:
                                    stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                    vendor = stripped[0]
                                    packageName = stripped[1] 
                                    packageVer = stripped[2]
                                    if packageVer == '*':
                                        try:
                                            versionStartIncluding = str(cpe['versionStartIncluding'])
                                        except:
                                            versionStartIncluding = 'NO_START'
                                        try:
                                            versionEndExcluding = str(cpe['versionEndExcluding'])
                                        except:
                                            versionEndExcluding = 'NOT_APPLICABLE'
                                    else:
                                        versionStartIncluding = 'NOT_APPLICABLE'
                                        versionEndExcluding = 'NOT_APPLICABLE'

                                    table.put_item(
                                        Item={
                                            'PackageName': packageName,
                                            'PackageVersion': packageVer,
                                            'CveId': cveId,
                                            'VersionStartIncluding': versionStartIncluding,
                                            'VersionEndExcluding': versionEndExcluding,
                                            'CveSourceUrl': cveSrcUrl,
                                            'CveDescription': cveDesc,
                                            'Reference': cveRef,
                                            'CvssV2Vector': cvssV2Vector,
                                            'CvssV2Score': json.loads(json.dumps(cvssV2Score), parse_float=Decimal),
                                            'CvssV2Severity': cvssV2Severity,
                                            'CvssV2Version': cvssV2Version,
                                            'CvssV3Vector': cvssV3Vector,
                                            'CvssV3Score': json.loads(json.dumps(cvssV3Score), parse_float=Decimal),
                                            'CvssV3Severity': cvssV3Severity,
                                            'CvssV3Version': cvssV3Version,
                                            'Vendor': vendor
                                        }
                                    )
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2021 JSON and sent to DynamoDB!')