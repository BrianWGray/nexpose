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
$hostName = "nexpose-test"
$port = "3780"
$credentialId = 2 
$url = "https://${hostName}:${port}/api/3/asset_groups/"

# Build headers to send to the API. In this case we set the Basic authentication value
$table_headers = @{
    Authorization=("Basic {0}" -f $base64AuthInfo)
}

# If you wanted to build the content for a credential object you could build it like:
$body = @{
    description = "A Static Asset Group with Assets that are Linux Assets running Containers (With Low Access Complexity Vulnerabilities) for remediation purposes.",
    name = "Container Hosts - Linux"
    searchCriteria = @{
                    filters = [
                            @{  field = "operating-system",
                                operator = "contains",
                                value= "linux" },
                            @{  field = "containers",
                                operator = "are",
                                value = 0 },
                            @{  field = "cvss-access-complexity",
                                operator = "is",
                                value = "L" }
                    ];
                    match = "all"
    };
    type = "static"
}


# Build PUT Content using the existing credential object 
$json =  $body | Convertto-JSON

# Visual of the json being sent - just for show
$json

$data = Invoke-RestMethod -Method 'PUT' -Uri $url -ContentType $data_type -Headers $table_headers -Body $json;
