#!/bin/bash

echo "Updating and installing dependencies"

sudo apt update
sudo apt upgrade -y
sudo apt autoremove -y
pip3 install --upgrade pip
pip3 install awscli
pip3 install boto3

read -p 'DynamoDB Table Name: ' tablevar
read -p 'AWS Region to deploy DynamoDB: ' regionvar

echo "Creating a DynamoDB Table"

aws dynamodb create-table \
    --table-name $tablevar \
    --attribute-definitions AttributeName=PackageName,AttributeType=S AttributeName=PackageVersion,AttributeType=S \
    --key-schema AttributeName=PackageName,KeyType=HASH AttributeName=PackageVersion,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST
    --global-secondary-indexes \
        "[
            {
                \"IndexName\": \"CveId\",
                \"KeySchema\": [
                    {\"AttributeName\":\"CveId\",\"KeyType\":\"HASH\"}
                ],
                \"Projection\": {
                    \"ProjectionType\":\"ALL\",
                }
            }
        ]"

echo "Getting the latest NVD 1.1 JSON ZIP Files"

mkdir nvd-feeds

sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.zip -P /nvd-feeds/
sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip -P /nvd-feeds/
#sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2022.json.zip -P /nvd-feeds/
#sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip -P /nvd-feeds/
#sudo wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.zip -P /nvd-feeds/
# lol world ends here

echo "Got the latest NVD 1.1 JSON zip Files - dont forget to manually add next years feeds!"

echo "Unzipping all of the NVD 1.1 JSON ZIP Files!"

sudo unzip "/nvd-feeds/*.zip"

echo "Executing Python script to parse all NVD 1.1 JSON Files - now would be a good time to get a coffee..."

python3 jsonNVDLoader.py $tablevar $regionvar

echo "Python script and Bash Script Done - Happy Scanning!!"