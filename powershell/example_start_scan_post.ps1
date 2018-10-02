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

# Check out the following links to get yourself started: - BrianWGray
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod?view=powershell-6
# https://www.gngrninja.com/script-ninja/2016/7/24/powershell-getting-started-utilizing-the-web-part-2-invoke-restmethod
# https://127.0.0.1:3780/api/3/
# https://help.rapid7.com/insightvm/en-us/api/index.html

# Collects user credentials for login (Functional)
# I don't highly recommend this specific credential collection method it's just to get the script bootstrapped until you are more comfortable - BrianWGray
$creds = Get-Credential
$unsecureCreds = $creds.GetNetworkCredential()
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $unsecureCreds.UserName,$unsecureCreds.Password)))
Remove-Variable unsecureCreds

# Set the API URI to call : In this example we specify the site ID integer that we want to start a scan on - BrianWGray
# $url = "https://127.0.0.1:3780/api/3/sites/1/scans"

$data_type = "application/json"

# Build headers to send to the API. In this case we set the data type of the body content and the Basic authentication value
$table_headers = @{
"Content-Type" = $data_type
Authorization=("Basic {0}" -f $base64AuthInfo)
}

# Build a POST Body to send to the API
# There are other options but we are just providing a name for the scan for an example
# https://help.rapid7.com/insightvm/en-us/api/index.html#operation/startScan
$body = @{
    name="API Scan Start"
}
$json = $body | Convertto-JSON

# Interact with the API in this case send a POST request to the specified URL and supply a basic auth header with a base64 encoded username:password
# The $body variable holds the data that we want to provide to the API then we convert the $body content to $json format for the API to parse.
$data = Invoke-RestMethod -Method 'Post' -Uri $url -Headers $table_headers -Body $json

# Now we have a data object full of the API response content that can be manipulated for view however you would like. - BrianWGray
# $data | Get-Member # Show returned object attributes
$data.id # display the id of the scan that was started


