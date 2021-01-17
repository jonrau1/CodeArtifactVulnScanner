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
import boto3
import os
import re
import urllib
import gzip
import json
from decimal import Decimal
# create boto3 resource
dynamodb = boto3.resource('dynamodb')
# Env vars and regex
cpeAppRegex = re.compile('cpe:2.3.a:')
nvdFeedUrl = os.environ['NVD_MODIFIED_URL']
table = dynamodb.Table(os.environ['NVD_DDB_TABLE'])

def lambda_handler(event, context):

    try:
        urllib.request.urlretrieve(nvdFeedUrl, '/tmp/modified-feed.json.gz')
    except Exception as e:
        print('Failed to download latest feed! Exiting!')
        raise e
    
    with gzip.open('/tmp/modified-feed.json.gz') as nistmodjson:
        nistmod = json.load(nistmodjson)
        try:
            for x in nistmod['CVE_Items']:
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
                    cvssVersion = 'CVSSv2.0'
                    cvssVector = str(x['impact']['baseMetricV2']['cvssV2']['vectorString'])
                    cvssScore = float(x['impact']['baseMetricV2']['cvssV3']['baseScore'])
                    cvssSeverity = str(x['impact']['baseMetricV2']['severity'])
                except:
                    cvssVersion = 'CVSSv2.0'
                    cvssVector = 'Unknown'
                    cvssScore = float(0.0)
                    cvssSeverity = 'Unknown'
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
                                            pass
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
                                            'CvssVector': cvssVector,
                                            'CvssScore': json.loads(json.dumps(cvssScore), parse_float=Decimal),
                                            'CvssSeverity': cvssSeverity,
                                            'CvssVersion': cvssVersion,
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
                                                pass
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
                                                'CvssVector': cvssVector,
                                                'CvssScore': json.loads(json.dumps(cvssScore), parse_float=Decimal),
                                                'CvssSeverity': cvssSeverity,
                                                'CvssVersion': cvssVersion,
                                                'Vendor': vendor
                                            }
                                        )
                                    else:
                                        pass
        except Exception as e:
            print(e)