import sys
import json
import boto3
import re

'''
cveTable = sys.argv[1]

ddbr = boto3.resource('dynamodb')
table = ddbr.table(cveTable)
'''

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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                # allow us the easily pluck out the Package Name and Version
                                # has Position 0 is the Vendor Name - which we may not care about
                                stripped = cpeUri.replace('cpe:2.3:a:','').split(':')
                                package = stripped[1] + '.' + stripped[2]
                                # some CPE 23 URIs are formatted oddly and make a string such as 
                                # package:* - this is not useful for us so all we can do is drop it
                                # TODO: Find a better way (regex?) to parse out the package name & version
                                if stripped[2] == '*':
                                    pass
                                else:
                                    print('PACK ' + package + ' HAS VULN ' + cveId)
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
                                    package = stripped[1] + '.' + stripped[2]
                                    if stripped[2] == '*':
                                        pass
                                    else:
                                        print('PACK ' + package + ' HAS VULN ' + cveId)
                                else:
                                    pass
    except Exception as e:
        print(e)

print('Parsed NVD CVE 2021 JSON and sent to DynamoDB!')