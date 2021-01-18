import os
import json
import boto3
import datetime

cveTable = os.environ['NVD_DDB_TABLE']
sts = boto3.client('sts')
sechub = boto3.client('securityhub')
dynamodb = boto3.client('dynamodb')
homeAccount = sts.get_caller_identity()['Account']

def lambda_handler(event, context):
    json.dumps(event)
    pckgName = str(event['detail']['packageName'])
    try:
        pckgVer = float(event['detail']['packageVersion'])
    except:
        pckgVer = str(event['detail']['packageVersion'])

    eventId = str(event['id'])
    awsRegion = str(event['region'])
    awsAccount = str(event['account'])
    packageArn = str(event['resources'][0])
    domainName = str(event['detail']['domainName'])
    domainOwner = str(event['detail']['domainOwner'])
    repositoryName = str(event['detail']['repositoryName'])
    packageFormat = str(event['detail']['packageFormat'])
    packageNamespace = str(event['detail']['packageNamespace'])
    packageState = str(event['detail']['packageVersionState'])
    packageOperation = str(event['detail']['operationType'])

    try:
        response = dynamodb.scan(
            TableName=cveTable,
            ScanFilter={
                'PackageName': {
                    'AttributeValueList': [
                        {'S': pckgName}
                    ],
                    'ComparisonOperator': 'EQ'
                }
            }
        )
        if str(response['Items']) == '[]':
            print('There is not a package of that name!')
            #exit(0) this gives a runtime error
        else:
            # We found a package - now let's check if it is vulnerable
            for items in response['Items']:
                # If there is a wildcard that means there is likely a range of versions which are vulnerable or not
                if str(items['PackageVersion']['S']) == '*':
                    # If we return NO_START for "VersionStartIncluding" that means we have to perform a Lesser Than
                    # Against "VersionEndExcluding" -- if we have floats on both ends (from DDB and CWE) then we are
                    # actually good. If there is every a mismatch that means something weird is going on and we are
                    # going to have to do something really stupid...
                    if str(items['VersionStartIncluding']['S']) == 'NO_START':
                        if str(items['VersionEndExcluding']['S']) != 'NOT_APPLICABLE':
                            try:
                                ddbFloatCheck = float(items['VersionEndExcluding']['S'])
                                if str(type(pckgVer)) == "<class 'str'>":
                                    # If DDB has a float and cloudwatch gave us something without a float we will have to make one ourself
                                    # THIS CAN BE DANGEROUS AND CREATE FALSE POSTIVES!!
                                    fakeFloatPckgVer = pckgVer.split('.')
                                    newFakeFloat = fakeFloatPckgVer[0] + '.' + fakeFloatPckgVer[1]
                                    # Logic time
                                    if float(newFakeFloat) < float(ddbFloatCheck):
                                        sechubPayload = {
                                            'EventId': eventId,
                                            'Region': awsRegion,
                                            'Account': awsAccount,
                                            'PackageArn': packageArn,
                                            'DomainName': domainName,
                                            'DomainOwner': domainOwner,
                                            'RepositoryName': repositoryName,
                                            'PackageFormat': packageFormat,
                                            'PackageNamespace': packageNamespace,
                                            'PackageState': packageState,
                                            'PackageOperation': packageOperation,
                                            'CvssV2Score': float(items['CvssV2Score']['N']),
                                            'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                            'CvssV2Version': str(items['CvssV2Version']['S']),
                                            'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                            'CvssV3Score': float(items['CvssV3Score']['N']),
                                            'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                            'CvssV3Version': str(items['CvssV3Version']['S']),
                                            'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                            'ReferenceUrl': str(items['Reference']['S']),
                                            'CveUrl': str(items['CveSourceUrl']['S']),
                                            'CveId': str(items['CveId']['S']),
                                            'Vendor': str(items['Vendor']['S']),
                                            'PackageName': pckgName,
                                            'PackageVersion': pckgVer
                                        }
                                        create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is Vulnerable due to being less than ' + str(items['PackageName']['VersionEndExcluding']))
                                    else:
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                        #exit(0) this gives a runtime error
                                # Safe math logic if we have Floats on both ends
                                elif str(type(pckgVer)) == "<class 'float'>":
                                    if pckgVer < ddbFloatCheck:
                                        sechubPayload = {
                                            'EventId': eventId,
                                            'Region': awsRegion,
                                            'Account': awsAccount,
                                            'PackageArn': packageArn,
                                            'DomainName': domainName,
                                            'DomainOwner': domainOwner,
                                            'RepositoryName': repositoryName,
                                            'PackageFormat': packageFormat,
                                            'PackageNamespace': packageNamespace,
                                            'PackageState': packageState,
                                            'PackageOperation': packageOperation,
                                            'CvssV2Score': float(items['CvssV2Score']['N']),
                                            'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                            'CvssV2Version': str(items['CvssV2Version']['S']),
                                            'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                            'CvssV3Score': float(items['CvssV3Score']['N']),
                                            'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                            'CvssV3Version': str(items['CvssV3Version']['S']),
                                            'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                            'ReferenceUrl': str(items['Reference']['S']),
                                            'CveUrl': str(items['CveSourceUrl']['S']),
                                            'CveId': str(items['CveId']['S']),
                                            'Vendor': str(items['Vendor']['S']),
                                            'PackageName': pckgName,
                                            'PackageVersion': pckgVer
                                        }
                                        create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is Vulnerable due to being less than ' + str(items['PackageName']['VersionEndExcluding']))
                                    else:
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                        #exit(0) this gives a runtime error
                                else:
                                    pass
                            except:
                                # Couldnt convert DynamoDB Key into a Float which means it has more than
                                # a single decimal place. Hopefully so does the package we are trying to compare to
                                ddbFloatCheck = str(items['VersionEndExcluding']['S'])
                                if str(type(pckgVer)) == "<class 'str'>":
                                    if str(pckgVer) == str(items['PackageVersion']['S']):
                                        sechubPayload = {
                                            'EventId': eventId,
                                            'Region': awsRegion,
                                            'Account': awsAccount,
                                            'PackageArn': packageArn,
                                            'DomainName': domainName,
                                            'DomainOwner': domainOwner,
                                            'RepositoryName': repositoryName,
                                            'PackageFormat': packageFormat,
                                            'PackageNamespace': packageNamespace,
                                            'PackageState': packageState,
                                            'PackageOperation': packageOperation,
                                            'CvssV2Score': float(items['CvssV2Score']['N']),
                                            'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                            'CvssV2Version': str(items['CvssV2Version']['S']),
                                            'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                            'CvssV3Score': float(items['CvssV3Score']['N']),
                                            'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                            'CvssV3Version': str(items['CvssV3Version']['S']),
                                            'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                            'ReferenceUrl': str(items['Reference']['S']),
                                            'CveUrl': str(items['CveSourceUrl']['S']),
                                            'CveId': str(items['CveId']['S']),
                                            'Vendor': str(items['Vendor']['S']),
                                            'PackageName': pckgName,
                                            'PackageVersion': pckgVer
                                        }
                                        create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is Vulnerable due to being less than ' + str(items['PackageName']['VersionEndExcluding']))
                                    else:
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                        #exit(0) this gives a runtime error
                                elif str(type(pckgVer)) == "<class 'float'>":
                                    # We have to make a float out of the DDB value because it was a string
                                    # but our version we got is a float
                                    fakeFloatDdb = ddbFloatCheck.split('.')
                                    newFakeDdbFloat = fakeFloatDdb[0] + '.' + fakeFloatDdb[1]
                                    if pckgVer < float(newFakeDdbFloat):
                                        sechubPayload = {
                                            'EventId': eventId,
                                            'Region': awsRegion,
                                            'Account': awsAccount,
                                            'PackageArn': packageArn,
                                            'DomainName': domainName,
                                            'DomainOwner': domainOwner,
                                            'RepositoryName': repositoryName,
                                            'PackageFormat': packageFormat,
                                            'PackageNamespace': packageNamespace,
                                            'PackageState': packageState,
                                            'PackageOperation': packageOperation,
                                            'CvssV2Score': float(items['CvssV2Score']['N']),
                                            'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                            'CvssV2Version': str(items['CvssV2Version']['S']),
                                            'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                            'CvssV3Score': float(items['CvssV3Score']['N']),
                                            'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                            'CvssV3Version': str(items['CvssV3Version']['S']),
                                            'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                            'ReferenceUrl': str(items['Reference']['S']),
                                            'CveUrl': str(items['CveSourceUrl']['S']),
                                            'CveId': str(items['CveId']['S']),
                                            'Vendor': str(items['Vendor']['S']),
                                            'PackageName': pckgName,
                                            'PackageVersion': pckgVer
                                        }
                                        create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is Vulnerable due to being less than ' + str(items['PackageName']['VersionEndExcluding']))
                                    else:
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                        #exit(0) this gives a runtime error
                                else:
                                    pass
                        else:
                            print('A VersionEndExcluding nor a VersionStartIncluding was provided for ' + str(items['PackageName']['S']) + ' so we need to exit')
                            exit(2)
                    else:
                        if str(items['VersionEndExcluding']['S']) != 'NOT_APPLICABLE':
                            ## To cut down on the code to check if we have mismatches between 3 variables and their 
                            ## types we are just going to do it all in one shot here
                            try:
                                startFloatCheck = float(items['VersionStartIncluding']['S'])
                                endFloatCheck = float(items['VersionEndExcluding']['S'])
                                if str(type(pckgVer)) == "<class 'str'>":
                                    fakeFloatPckgVer = pckgVer.split('.')
                                    newFakeFloat = fakeFloatPckgVer[0] + '.' + fakeFloatPckgVer[1]
                                    if float(newFakeFloat) >= startFloatCheck and float(newFakeFloat) < endFloatCheck:
                                        sechubPayload = {
                                            'EventId': eventId,
                                            'Region': awsRegion,
                                            'Account': awsAccount,
                                            'PackageArn': packageArn,
                                            'DomainName': domainName,
                                            'DomainOwner': domainOwner,
                                            'RepositoryName': repositoryName,
                                            'PackageFormat': packageFormat,
                                            'PackageNamespace': packageNamespace,
                                            'PackageState': packageState,
                                            'PackageOperation': packageOperation,
                                            'CvssV2Score': float(items['CvssV2Score']['N']),
                                            'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                            'CvssV2Version': str(items['CvssV2Version']['S']),
                                            'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                            'CvssV3Score': float(items['CvssV3Score']['N']),
                                            'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                            'CvssV3Version': str(items['CvssV3Version']['S']),
                                            'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                            'ReferenceUrl': str(items['Reference']['S']),
                                            'CveUrl': str(items['CveSourceUrl']['S']),
                                            'CveId': str(items['CveId']['S']),
                                            'Vendor': str(items['Vendor']['S']),
                                            'PackageName': pckgName,
                                            'PackageVersion': pckgVer
                                        }
                                        create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is vulnerable because it is great than or equal to ' 
                                            + str(items['VersionStartIncluding']['S']) + ' but is lesser than ' + str(items['VersionEndExcluding']['S'])
                                        )
                                    else:
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                        #exit(0) this gives a runtime error
                                elif str(type(pckgVer)) == "<class 'float'>":
                                    if pckgVer >= startFloatCheck and pckgVer < endFloatCheck:
                                        sechubPayload = {
                                            'EventId': eventId,
                                            'Region': awsRegion,
                                            'Account': awsAccount,
                                            'PackageArn': packageArn,
                                            'DomainName': domainName,
                                            'DomainOwner': domainOwner,
                                            'RepositoryName': repositoryName,
                                            'PackageFormat': packageFormat,
                                            'PackageNamespace': packageNamespace,
                                            'PackageState': packageState,
                                            'PackageOperation': packageOperation,
                                            'CvssV2Score': float(items['CvssV2Score']['N']),
                                            'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                            'CvssV2Version': str(items['CvssV2Version']['S']),
                                            'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                            'CvssV3Score': float(items['CvssV3Score']['N']),
                                            'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                            'CvssV3Version': str(items['CvssV3Version']['S']),
                                            'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                            'ReferenceUrl': str(items['Reference']['S']),
                                            'CveUrl': str(items['CveSourceUrl']['S']),
                                            'CveId': str(items['CveId']['S']),
                                            'Vendor': str(items['Vendor']['S']),
                                            'PackageName': pckgName,
                                            'PackageVersion': pckgVer
                                        }
                                        create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is vulnerable because it is great than or equal to ' 
                                            + str(items['VersionStartIncluding']['S']) + ' but is lesser than ' + str(items['VersionEndExcluding']['S'])
                                        )
                                    else:
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                        #exit(0) this gives a runtime error
                            except:
                                startFloatCheck = str(items['VersionStartIncluding']['S'])
                                endFloatCheck = str(items['VersionEndExcluding']['S'])
                                startFloatSplitter = startFloatCheck.split('.')
                                endFloatSplitter = endFloatCheck.split('.')
                                fakeStartFloat = startFloatSplitter[0] + '.' + startFloatSplitter[1]
                                fakeEndFloat = endFloatSplitter[0] + '.' + endFloatSplitter[1]
                                if str(type(pckgVer)) == "<class 'str'>":
                                    fakeFloatPckgVer = pckgVer.split('.')
                                    newFakeFloat = fakeFloatPckgVer[0] + '.' + fakeFloatPckgVer[1]
                                    # Check if we are greater than or equal to the Start Version and are
                                    # less than the End Version
                                    if float(newFakeFloat) >= float(fakeStartFloat) and newFakeFloat < float(fakeEndFloat):
                                        sechubPayload = {
                                            'EventId': eventId,
                                            'Region': awsRegion,
                                            'Account': awsAccount,
                                            'PackageArn': packageArn,
                                            'DomainName': domainName,
                                            'DomainOwner': domainOwner,
                                            'RepositoryName': repositoryName,
                                            'PackageFormat': packageFormat,
                                            'PackageNamespace': packageNamespace,
                                            'PackageState': packageState,
                                            'PackageOperation': packageOperation,
                                            'CvssV2Score': float(items['CvssV2Score']['N']),
                                            'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                            'CvssV2Version': str(items['CvssV2Version']['S']),
                                            'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                            'CvssV3Score': float(items['CvssV3Score']['N']),
                                            'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                            'CvssV3Version': str(items['CvssV3Version']['S']),
                                            'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                            'ReferenceUrl': str(items['Reference']['S']),
                                            'CveUrl': str(items['CveSourceUrl']['S']),
                                            'CveId': str(items['CveId']['S']),
                                            'Vendor': str(items['Vendor']['S']),
                                            'PackageName': pckgName,
                                            'PackageVersion': pckgVer
                                        }
                                        create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is vulnerable because it is great than or equal to ' 
                                            + str(items['VersionStartIncluding']['S']) + ' but is lesser than ' + str(items['VersionEndExcluding']['S'])
                                        )
                                    else:
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + 
                                            str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S'])
                                        )
                                        #exit(0) this gives a runtime error
                                elif str(type(pckgVer)) == "<class 'float'>":
                                    # Check if we are greater than or equal to the Start Version and are
                                    # less than the End Version
                                    if pckgVer >= float(fakeStartFloat) and pckgVer < float(fakeEndFloat):
                                        sechubPayload = {
                                            'EventId': eventId,
                                            'Region': awsRegion,
                                            'Account': awsAccount,
                                            'PackageArn': packageArn,
                                            'DomainName': domainName,
                                            'DomainOwner': domainOwner,
                                            'RepositoryName': repositoryName,
                                            'PackageFormat': packageFormat,
                                            'PackageNamespace': packageNamespace,
                                            'PackageState': packageState,
                                            'PackageOperation': packageOperation,
                                            'CvssV2Score': float(items['CvssV2Score']['N']),
                                            'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                            'CvssV2Version': str(items['CvssV2Version']['S']),
                                            'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                            'CvssV3Score': float(items['CvssV3Score']['N']),
                                            'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                            'CvssV3Version': str(items['CvssV3Version']['S']),
                                            'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                            'ReferenceUrl': str(items['Reference']['S']),
                                            'CveUrl': str(items['CveSourceUrl']['S']),
                                            'CveId': str(items['CveId']['S']),
                                            'Vendor': str(items['Vendor']['S']),
                                            'PackageName': pckgName,
                                            'PackageVersion': pckgVer
                                        }
                                        create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is vulnerable because it is great than or equal to ' 
                                            + str(items['VersionStartIncluding']['S']) + ' but is lesser than ' + str(items['VersionEndExcluding']['S'])
                                        )
                                    else:
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                        #exit(0) this gives a runtime error
                        else:
                            try:
                                startFloatCheck = float(items['VersionStartIncluding']['S'])
                                if str(type(pckgVer)) == "<class 'str'>":
                                    fakeFloatPckgVer = pckgVer.split('.')
                                    newFakeFloat = fakeFloatPckgVer[0] + '.' + fakeFloatPckgVer[1]
                                    if float(newFakeFloat) >= startFloatCheck:
                                        sechubPayload = {
                                            'EventId': eventId,
                                            'Region': awsRegion,
                                            'Account': awsAccount,
                                            'PackageArn': packageArn,
                                            'DomainName': domainName,
                                            'DomainOwner': domainOwner,
                                            'RepositoryName': repositoryName,
                                            'PackageFormat': packageFormat,
                                            'PackageNamespace': packageNamespace,
                                            'PackageState': packageState,
                                            'PackageOperation': packageOperation,
                                            'CvssV2Score': float(items['CvssV2Score']['N']),
                                            'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                            'CvssV2Version': str(items['CvssV2Version']['S']),
                                            'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                            'CvssV3Score': float(items['CvssV3Score']['N']),
                                            'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                            'CvssV3Version': str(items['CvssV3Version']['S']),
                                            'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                            'ReferenceUrl': str(items['Reference']['S']),
                                            'CveUrl': str(items['CveSourceUrl']['S']),
                                            'CveId': str(items['CveId']['S']),
                                            'Vendor': str(items['Vendor']['S']),
                                            'PackageName': pckgName,
                                            'PackageVersion': pckgVer
                                        }
                                        create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is Vulnerable due to being greater than or equal to ' + str(items['VersionStartIncluding']['S']))
                                    else:
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                        #exit(0) this gives a runtime error
                                elif str(type(pckgVer)) == "<class 'float'>":
                                    if pckgVer >= startFloatCheck:
                                        sechubPayload = {
                                            'EventId': eventId,
                                            'Region': awsRegion,
                                            'Account': awsAccount,
                                            'PackageArn': packageArn,
                                            'DomainName': domainName,
                                            'DomainOwner': domainOwner,
                                            'RepositoryName': repositoryName,
                                            'PackageFormat': packageFormat,
                                            'PackageNamespace': packageNamespace,
                                            'PackageState': packageState,
                                            'PackageOperation': packageOperation,
                                            'CvssV2Score': float(items['CvssV2Score']['N']),
                                            'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                            'CvssV2Version': str(items['CvssV2Version']['S']),
                                            'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                            'CvssV3Score': float(items['CvssV3Score']['N']),
                                            'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                            'CvssV3Version': str(items['CvssV3Version']['S']),
                                            'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                            'ReferenceUrl': str(items['Reference']['S']),
                                            'CveUrl': str(items['CveSourceUrl']['S']),
                                            'CveId': str(items['CveId']['S']),
                                            'Vendor': str(items['Vendor']['S']),
                                            'PackageName': pckgName,
                                            'PackageVersion': pckgVer
                                        }
                                        create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is Vulnerable due to being greater than or equal to ' + str(items['VersionStartIncluding']['S']))
                                    else:
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                        #exit(0) this gives a runtime error
                            except:
                                startFloatCheck = str(items['VersionStartIncluding']['S'])
                                startFloatSplitter = startFloatCheck.split('.')
                                fakeStartFloat = startFloatSplitter[0] + '.' + startFloatSplitter[1]
                                if str(type(pckgVer)) == "<class 'str'>":
                                    fakeFloatPckgVer = pckgVer.split('.')
                                    newFakeFloat = fakeFloatPckgVer[0] + '.' + fakeFloatPckgVer[1]
                                    # Check if we are greater than or equal to the Start Version and are
                                    # less than the End Version
                                    if float(newFakeFloat) >= float(fakeStartFloat):
                                        sechubPayload = {
                                            'EventId': eventId,
                                            'Region': awsRegion,
                                            'Account': awsAccount,
                                            'PackageArn': packageArn,
                                            'DomainName': domainName,
                                            'DomainOwner': domainOwner,
                                            'RepositoryName': repositoryName,
                                            'PackageFormat': packageFormat,
                                            'PackageNamespace': packageNamespace,
                                            'PackageState': packageState,
                                            'PackageOperation': packageOperation,
                                            'CvssV2Score': float(items['CvssV2Score']['N']),
                                            'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                            'CvssV2Version': str(items['CvssV2Version']['S']),
                                            'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                            'CvssV3Score': float(items['CvssV3Score']['N']),
                                            'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                            'CvssV3Version': str(items['CvssV3Version']['S']),
                                            'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                            'ReferenceUrl': str(items['Reference']['S']),
                                            'CveUrl': str(items['CveSourceUrl']['S']),
                                            'CveId': str(items['CveId']['S']),
                                            'Vendor': str(items['Vendor']['S']),
                                            'PackageName': pckgName,
                                            'PackageVersion': pckgVer
                                        }
                                        create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is Vulnerable due to being greater than or equal to ' + str(items['VersionStartIncluding']['S']))
                                    else:
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                        #exit(0) this gives a runtime error
                                elif str(type(pckgVer)) == "<class 'float'>":
                                    # Check if we are greater than or equal to the Start Version and are
                                    # less than the End Version
                                    if pckgVer >= float(fakeStartFloat):
                                        sechubPayload = {
                                            'EventId': eventId,
                                            'Region': awsRegion,
                                            'Account': awsAccount,
                                            'PackageArn': packageArn,
                                            'DomainName': domainName,
                                            'DomainOwner': domainOwner,
                                            'RepositoryName': repositoryName,
                                            'PackageFormat': packageFormat,
                                            'PackageNamespace': packageNamespace,
                                            'PackageState': packageState,
                                            'PackageOperation': packageOperation,
                                            'CvssV2Score': float(items['CvssV2Score']['N']),
                                            'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                            'CvssV2Version': str(items['CvssV2Version']['S']),
                                            'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                            'CvssV3Score': float(items['CvssV3Score']['N']),
                                            'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                            'CvssV3Version': str(items['CvssV3Version']['S']),
                                            'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                            'ReferenceUrl': str(items['Reference']['S']),
                                            'CveUrl': str(items['CveSourceUrl']['S']),
                                            'CveId': str(items['CveId']['S']),
                                            'Vendor': str(items['Vendor']['S']),
                                            'PackageName': pckgName,
                                            'PackageVersion': pckgVer
                                        }
                                        create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is Vulnerable due to being greater than or equal to ' + str(items['VersionStartIncluding']['S']))
                                    else:
                                        print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                        #exit(0) this gives a runtime error
                            
                # If there is NOT a wildcard that is actually a much better outcome. Hopefully we have "legal" floats
                # on both ends - or strings on both ends. If not we will have to be do some things equally questionable
                # like creating a fake float which AGAIN - CAN CAUSE FALSE POSITIVES OR FALSE NEGATIVES!!!
                else:
                    if str(type(pckgVer)) == "<class 'str'>":
                        if str(pckgVer) == str(items['PackageVersion']['S']):
                            sechubPayload = {
                                'EventId': eventId,
                                'Region': awsRegion,
                                'Account': awsAccount,
                                'PackageArn': packageArn,
                                'DomainName': domainName,
                                'DomainOwner': domainOwner,
                                'RepositoryName': repositoryName,
                                'PackageFormat': packageFormat,
                                'PackageNamespace': packageNamespace,
                                'PackageState': packageState,
                                'PackageOperation': packageOperation,
                                'CvssV2Score': float(items['CvssV2Score']['N']),
                                'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                'CvssV2Version': str(items['CvssV2Version']['S']),
                                'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                'CvssV3Score': float(items['CvssV3Score']['N']),
                                'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                'CvssV3Version': str(items['CvssV3Version']['S']),
                                'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                'ReferenceUrl': str(items['Reference']['S']),
                                'CveUrl': str(items['CveSourceUrl']['S']),
                                'CveId': str(items['CveId']['S']),
                                'Vendor': str(items['Vendor']['S']),
                                'PackageName': pckgName,
                                'PackageVersion': pckgVer
                            }
                            create_securityhub_finding(json.dumps(sechubPayload, default=str))
                            print(str(pckgName) + '.' + str(pckgVer) + ' is vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                        else:
                            print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                            #exit(0) this gives a runtime error
                    elif str(type(pckgVer)) == "<class 'float'>":
                        try:
                            ddbVersionFloat = float(items['PackageVersion']['S'])
                            if pckgVer == ddbVersionFloat:
                                sechubPayload = {
                                    'EventId': eventId,
                                    'Region': awsRegion,
                                    'Account': awsAccount,
                                    'PackageArn': packageArn,
                                    'DomainName': domainName,
                                    'DomainOwner': domainOwner,
                                    'RepositoryName': repositoryName,
                                    'PackageFormat': packageFormat,
                                    'PackageNamespace': packageNamespace,
                                    'PackageState': packageState,
                                    'PackageOperation': packageOperation,
                                    'CvssV2Score': float(items['CvssV2Score']['N']),
                                    'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                    'CvssV2Version': str(items['CvssV2Version']['S']),
                                    'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                    'CvssV3Score': float(items['CvssV3Score']['N']),
                                    'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                    'CvssV3Version': str(items['CvssV3Version']['S']),
                                    'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                    'ReferenceUrl': str(items['Reference']['S']),
                                    'CveUrl': str(items['CveSourceUrl']['S']),
                                    'CveId': str(items['CveId']['S']),
                                    'Vendor': str(items['Vendor']['S']),
                                    'PackageName': pckgName,
                                    'PackageVersion': pckgVer
                                }
                                create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                print(str(pckgName) + '.' + str(pckgVer) + ' is vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                            else:
                                print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                #exit(0) this gives a runtime error
                        except:
                            ddbVersionFloat = str(items['PackageVersion']['S'])
                            ddbVersionFloatSplitter = ddbVersionFloat.split('.')
                            newddbVersionFloat = ddbVersionFloatSplitter[0] + '.' + ddbVersionFloatSplitter[1]
                            if pckgVer == float(newddbVersionFloat):
                                sechubPayload = {
                                    'EventId': eventId,
                                    'Region': awsRegion,
                                    'Account': awsAccount,
                                    'PackageArn': packageArn,
                                    'DomainName': domainName,
                                    'DomainOwner': domainOwner,
                                    'RepositoryName': repositoryName,
                                    'PackageFormat': packageFormat,
                                    'PackageNamespace': packageNamespace,
                                    'PackageState': packageState,
                                    'PackageOperation': packageOperation,
                                    'CvssV2Score': float(items['CvssV2Score']['N']),
                                    'CvssV2Vector': str(items['CvssV2Vector']['S']),
                                    'CvssV2Version': str(items['CvssV2Version']['S']),
                                    'CvssV2Severity': str(items['CvssV2Severity']['S']),
                                    'CvssV3Score': float(items['CvssV3Score']['N']),
                                    'CvssV3Vector': str(items['CvssV3Vector']['S']),
                                    'CvssV3Version': str(items['CvssV3Version']['S']),
                                    'CvssV3Severity': str(items['CvssV3Severity']['S']),
                                    'ReferenceUrl': str(items['Reference']['S']),
                                    'CveUrl': str(items['CveSourceUrl']['S']),
                                    'CveId': str(items['CveId']['S']),
                                    'Vendor': str(items['Vendor']['S']),
                                    'PackageName': pckgName,
                                    'PackageVersion': pckgVer
                                }
                                create_securityhub_finding(json.dumps(sechubPayload, default=str))
                                print(str(pckgName) + '.' + str(pckgVer) + ' is vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                            else:
                                print(str(pckgName) + '.' + str(pckgVer) + ' is not vulnerable compared to ' + str(items['PackageName']['S']) + '.' + str(items['PackageVersion']['S']))
                                #exit(0) this gives a runtime error
                    else:
                        pass
    except Exception as e:
        raise e

def create_securityhub_finding(sechubPayload):
    # Mapping to match CVSS severity against the Security Hub Severity Label...
    if str(json.loads(sechubPayload)['CvssV3Severity']) != 'Unknown':
        sechubSev = str(json.loads(sechubPayload)['CvssV3Severity'])
    else:
        if str(json.loads(sechubPayload)['CvssV2Severity']) != 'Unknown':
            sechubSev = str(json.loads(sechubPayload)['CvssV2Severity'])
        else:
            sechubSev = 'MEDIUM'

    try:
        sechub.batch_import_findings(
            Findings=[
                {
                    'SchemaVersion': '2018-10-08',
                    'Id': json.loads(sechubPayload)['PackageArn'] + 'vulnerability-found-' + json.loads(sechubPayload)['CveId'],
                    'ProductArn': 'arn:aws:securityhub:' + 
                        json.loads(sechubPayload)['Region'] + ':' + 
                        json.loads(sechubPayload)['Account'] + ':product/' + 
                        json.loads(sechubPayload)['Account'] + '/default',
                    'GeneratorId': json.loads(sechubPayload)['EventId'],
                    'AwsAccountId': json.loads(sechubPayload)['Account'],
                    'Types': ['Software and Configuration Checks/Vulnerabilities/CVE'],
                    'CreatedAt': datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat(),
                    'UpdatedAt': datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat(),
                    'Severity': {'Label': sechubSev},
                    'Title': '[OpenCAVS] A software package with a known vulnerability was found in AWS CodeArtifact',
                    'Description': 'The software package in ' +
                        json.loads(sechubPayload)['RepositoryName'] +
                        ' ' + json.loads(sechubPayload)['PackageName'] + '.' +
                        str(json.loads(sechubPayload)['PackageVersion']) + ' is vulnerable to ' +
                        json.loads(sechubPayload)['CveId'],
                    'Remediation': {
                        'Recommendation': {
                            'Text': 'If possible, update the Package Version to the latest version that is not vulnerable within CodeArtifact',
                            'Url': 'https://docs.aws.amazon.com/codeartifact/latest/ug/describe-package-version.html'
                        }
                    },
                    'ProductFields': {'ProductName': 'OpenCAVS'},
                    'Resources': [
                        {
                            'Type': 'AwsCodeArtifactPackage',
                            'Id': json.loads(sechubPayload)['PackageArn'],
                            'Partition': 'aws',
                            'Region': json.loads(sechubPayload)['Region'],
                            'Details': {
                                'Other': {
                                    'DomainName': json.loads(sechubPayload)['DomainName'],
                                    'DomainOwner': json.loads(sechubPayload)['DomainOwner'],
                                    'RepositoryName': json.loads(sechubPayload)['RepositoryName'],
                                    'PackageFormat': json.loads(sechubPayload)['PackageFormat'],
                                    'PackageNamespace': json.loads(sechubPayload)['PackageNamespace'],
                                    'PackageState': json.loads(sechubPayload)['PackageState'],
                                    'PackageOperation': json.loads(sechubPayload)['PackageOperation'],
                                    'PackageName': json.loads(sechubPayload)['PackageName'],
                                    'PackageVersion': str(json.loads(sechubPayload)['PackageVersion']),
                                    'Vendor': json.loads(sechubPayload)['Vendor']
                                }
                            }
                        },
                    ],
                    'Compliance': {'Status': 'FAILED'},
                    'WorkflowState': 'NEW',
                    'Workflow': {'Status': 'NEW'},
                    'RecordState': 'ACTIVE',
                    'Vulnerabilities': [
                        {
                            'Id': json.loads(sechubPayload)['CveId'],
                            'VulnerablePackages': [
                                {
                                    'Name': json.loads(sechubPayload)['PackageName'],
                                    'Version': str(json.loads(sechubPayload)['PackageVersion'])
                                }
                            ],
                            'Cvss': [
                                {
                                    'Version': json.loads(sechubPayload)['CvssV2Version'],
                                    'BaseScore': float(json.loads(sechubPayload)['CvssV2Score']),
                                    'BaseVector': json.loads(sechubPayload)['CvssV2Vector']
                                },
                                {
                                    'Version': json.loads(sechubPayload)['CvssV3Version'],
                                    'BaseScore': float(json.loads(sechubPayload)['CvssV3Score']),
                                    'BaseVector': json.loads(sechubPayload)['CvssV3Vector']
                                },
                            ],
                            'Vendor': {'Name': json.loads(sechubPayload)['Vendor']},
                            'ReferenceUrls': [
                                json.loads(sechubPayload)['ReferenceUrl'],
                                json.loads(sechubPayload)['CveUrl']
                            ]
                        },
                    ]
                }
            ]
        )
        print('Finding created in Security Hub')
    except Exception as e:
        print(e)