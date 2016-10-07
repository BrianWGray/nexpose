#!/usr/bin/env ruby
# Brian W. Gray
# 010.07.2016


## Script Heavily borrows from Steve Tempest : https://community.rapid7.com/docs/DOC-2733 , https://community.rapid7.com/docs/DOC-2732
## Written as PoC for https://community.rapid7.com/thread/9132

## Script performs the following tasks
## 1.) Read addresses from text file
## 2.) De-duplicate addresses
## 3.) Scan addresses
## 4.) Generate a report of vulnerabilities detected during the scan.


require 'yaml'
require 'nexpose'
require 'csv'
include Nexpose

# Default Values

config = YAML.load_file("conf/nexpose.yaml") # From file

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]
@nexposeAjaxTimeout = config["nexposeajaxtimeout"]

@name = nil

# Any arguments after flags can be grabbed now."
unless ARGV[0]
    $stderr.puts 'Input file and site id is required.'
    exit(1)
end
file = ARGV[0]
@name = File.basename(file, File.extname(file)) unless @name

siteID = 0
siteID = ARGV[1]

# This will fail if the file cannot be read.
ips = File.read(file).split.uniq

nsc = Nexpose::Connection.new(@host, @userid, @password, @port)

begin
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end

at_exit { nsc.logout }

## Initialize connection timeout values.
## Timeout example provided by JGreen in https://community.rapid7.com/thread/5075

module Nexpose
    class APIRequest
        include XMLUtils
        # Execute an API request
        def self.execute(url, req, api_version='2.0', options = {})
        options = {timeout: @nexposeAjaxTimeout}
        obj = self.new(req.to_s, url, api_version)
        obj.execute(options)
        return obj
    end
end


module AJAX
    def self._https(nsc)
    http = Net::HTTP.new(nsc.host, nsc.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.read_timeout = @nexposeAjaxTimeout
    http
end
end
end


# Create a map of all assets by IP to make them quicker to find.
all_assets = nsc.assets.reduce({}) do |hash, dev|
    $stderr.puts("Duplicate asset: #{dev.address}") if @debug and hash.member? dev.address
    hash[dev.address] = dev
    hash
end

# Collect Site info to provide additional information for screen output.
siteInfo = nsc.sites
siteDetail = Site.load(nsc, siteID)
@name = siteDetail.name

puts "Starting partial scan of siteID #{siteID} "
#scan = site.scan(nsc) 

scan = nsc.scan_ips(siteID, ips)


begin
	sleep(15)
	status = nsc.scan_status(scan.id)
  puts "ScanID: #{scan.id} ScanTemplate: #{siteDetail.scan_template_id}, SiteID: #{siteID} - #{siteDetail.name}, Status:#{status}, EngineID:#{scan.engine}"
end while status == Nexpose::Scan::Status::RUNNING


sqlSelect = "
WITH
asset_ips AS (
              SELECT asset_id, ip_address, type
              FROM dim_asset_ip_address dips
              ),
asset_addresses AS (
                    SELECT da.asset_id,
                    (SELECT array_to_string(array_agg(ip_address), ',') FROM asset_ips WHERE asset_id = da.asset_id AND type = 'IPv4') AS ipv4s,
                    (SELECT array_to_string(array_agg(ip_address), ',') FROM asset_ips WHERE asset_id = da.asset_id AND type = 'IPv6') AS ipv6s,
                    (SELECT array_to_string(array_agg(mac_address), ',') FROM dim_asset_mac_address WHERE asset_id = da.asset_id) AS macs
                    FROM dim_asset da
                    JOIN asset_ips USING (asset_id)
                    ),
asset_names AS (
                SELECT asset_id, array_to_string(array_agg(host_name), ',') AS names
                FROM dim_asset_host_name
                GROUP BY asset_id
                ),
asset_facts AS (
                SELECT asset_id, riskscore, exploits, malware_kits
                FROM fact_asset
                ),
vulnerability_metadata AS (
                           SELECT *
                           FROM dim_vulnerability dv
                           ),
vuln_cves_ids AS (
                  SELECT vulnerability_id, array_to_string(array_agg(reference), ',') AS cves
                  FROM dim_vulnerability_reference
                  WHERE source = 'CVE'
                  GROUP BY vulnerability_id
                  )


SELECT
da.ip_address AS \"Asset IP Address\",
favi.port AS \"Service Port\",
dp.name AS \"Service Protocol\",
dsvc.name AS \"Service Name\",
an.names AS \"Asset Names\",
favi.date AS \"Vulnerability Test Date\",
dsc.started AS \"Last Scan Time\",
favi.scan_id AS \"Scan ID\",
ds.name AS \"Site Name\",
ds.importance AS \"Site Importance\",
vm.date_published AS \"Vulnerability Published Date\",
ROUND((EXTRACT(epoch FROM age(now(), date_published)) / (60 * 60 * 24))::numeric, 0) AS \"Vulnerability Age\",
cves.cves AS \"Vulnerability CVE IDs\",
vm.title AS \"Vulnerability Title\",
vm.cvss_score AS \"Vulnerability CVSS Score\",
proofAsText(vm.description) AS \"Vulnerability Description\",
vm.nexpose_id AS \"Vulnerability ID\",
vm.severity AS \"Vulnerability Severity Level\",
dvs.description AS \"Vulnerability Test Result Description\"


FROM fact_asset_vulnerability_instance favi
JOIN dim_asset da USING (asset_id)
LEFT OUTER JOIN asset_addresses aa USING (asset_id)
LEFT OUTER JOIN asset_names an USING (asset_id)
JOIN asset_facts af USING (asset_id)
JOIN dim_service dsvc USING (service_id)
JOIN dim_protocol dp USING (protocol_id)
JOIN dim_site_asset dsa USING (asset_id)
JOIN dim_site ds USING (site_id)
JOIN vulnerability_metadata vm USING (vulnerability_id)
JOIN dim_vulnerability_status dvs USING (status_id)
JOIN dim_operating_system dos USING (operating_system_id)
LEFT OUTER JOIN dim_scan dsc USING (scan_id)
LEFT OUTER JOIN vuln_cves_ids cves USING (vulnerability_id) "

sqlWhere = ""
orderBy = " ORDER BY da.ip_address;"

query = sqlSelect + sqlWhere + orderBy

puts "Initiating Report"

report = Nexpose::AdhocReportConfig.new(nil, 'sql')
report.add_filter('version', '1.2.1')
report.add_filter('query', query)
report.add_filter('scan', scan.id) # filter the report scope based on the scanID that was just run.
report_output = report.generate(nsc)
csv_output = CSV.parse(report_output.chomp, { :headers => :first_row })
CSV.open("adhoc_SiteID_#{siteID}_Report.csv", 'w') do |csv_file|
    csv_file << csv_output.headers
    csv_output.each do |row|
        csv_file << row
    end
end

puts 'Report completed and saved'

exit
