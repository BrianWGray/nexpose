# Attempt to help with https://kb.help.rapid7.com/discuss/5c66e04394dea300577d6d47

# Makes PS ignore self signed certs used by internal servers
# Have someone actually sign this certificate... - BrianWGray

if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()
# https://help.rapid7.com/insightvm/en-us/api/index.html
# https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssetGroups

# Collects user credentials for login (Functional)
$creds = Get-Credential
$unsecureCreds = $creds.GetNetworkCredential()
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $unsecureCreds.UserName,$unsecureCreds.Password)))
Remove-Variable unsecureCreds

# Define data transfer type
$data_type = "application/json"

# URL Definintions
$hostName = "nexpose-test.example.com"
$port = "3780"
$url = "https://${hostName}:${port}/api/3/asset_groups/"

# Build headers to send to the API. In this case we set the Basic authentication value
$table_headers = @{
"Content-Type" = $data_type
Authorization=("Basic {0}" -f $base64AuthInfo)
}

# Search filter criteria

$filter = @{ field = "operating-system"; operator = "contains"; value = "linux"}

$filters = @($filter)

# Here we're using straight JSON to prove API / documentation issues 
$body = @"
{
    "description": "A Static Asset Group with Assets that are Linux Assets running Containers (With Low Access Complexity Vulnerabilities) for remediation purposes.",
    "name": "Container Hosts - Linux",
    "searchCriteria": {
        "filters": [
            { "field": "operating-system", "operator": "contains", "value": "linux" },
            { "field": "containers", "operator": "are", "value": 0 },
            { "field": "cvss-access-complexity", "operator": "is", "value": "L" }
        ],
        "match": "all"
    },
    "type": "static"
}

"@

# Build Post Content using the existing credential object 
# We don't need to use the convert to JSON in this example but left it for additional testing.
$json = $body # | Convertto-JSON

# Visual of the json being sent - just for show
$json

$data = Invoke-RestMethod -Method 'Post' -Uri $url -Headers $table_headers -Body $json