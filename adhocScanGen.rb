#!/usr/bin/env ruby
# Brian W. Gray
# 07.25.2014

## Script Heavily borrows from Steve Tempest : https://community.rapid7.com/docs/DOC-2733 , https://community.rapid7.com/docs/DOC-2732

## Script performs the following tasks
## 1.) Read addresses from text file
## 2.) De-duplicate addresses
## 3.) Create new temporary site
## 4.) Add addresses to the created site
## 5.) Specify scan engine and template to use from nexpose.yaml
## 6.) Perform scan of the temporary site.
## 7.) Generate a report of vulnerabilities detected
## 8.) Delete temporary site.

require 'yaml'
require 'nexpose'
require 'optparse'
require 'highline/import'
require 'csv'


# Default Values

config = YAML.load_file("conf/nexpose.yaml") # From file

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]
@scanTemplate = config["adhocscantemplate"]
@scanEngine = config["adhocscanengine"]


@name = @desc = nil

OptionParser.new do |opts|
    opts.banner = "Usage: #{File::basename($0)} [options]"
    opts.separator ''
    opts.separator 'Create a temporary site based upon an input file, one address per line, scans, reports findings, then deletes the site.'
    opts.separator ''
    opts.separator 'By default, the filename is used as the name of the adhoc site, if --name is not provided.'
    opts.separator ''
    opts.separator 'Options:'
    opts.on('-n', '--name [NAME]', 'Name to use for the adhoc site. Must not already exist.') { |name| @name = name }
    opts.on('-d', '--desc [DESCRIPTION]', 'Description to use for new asset group.') { |desc| @desc = desc }
    opts.on('-x', '--debug', 'Report duplicate IP addresses to STDERR.') { |debug| @debug = debug }
    opts.on_tail('--help', 'Print this help message.') { puts opts; exit }
end.parse!


# Any arguments after flags can be grabbed now."
unless ARGV[0]
    $stderr.puts 'Input file is required.'
    exit(1)
end
file = ARGV[0]
@name = File.basename(file, File.extname(file)) unless @name

# This will fail if the file cannot be read.
ips = File.read(file).split.uniq

nsc = Nexpose::Connection.new(@host, @userid, @password, @port)
puts 'logging into Nexpose'

begin
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{e.reason}")
    exit(1)
end

puts 'logged into Nexpose'
at_exit { nsc.logout }

# Create a map of all assets by IP to make them quicker to find.
all_assets = nsc.assets.reduce({}) do |hash, dev|
    $stderr.puts("Duplicate asset: #{dev.address}") if @debug and hash.member? dev.address
    hash[dev.address] = dev
    hash
end

puts "Creating site #{@name}"

site = Nexpose::Site.new(@name, @scanTemplate)
site.description = @desc
site.engine = @scanEngine

ips.each do |ip|
    site.add_asset(ip)
    puts "Adding #{ip} to site #{@name}"
end

site.save(nsc)

puts 'Create site successfully'

puts "Starting scan of adhoc site #{@name} "
scan = site.scan(nsc) 


begin
	sleep(15)
	status = nsc.scan_status(scan.id)
	puts "Current scan status: #{status.to_s}"
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

sqlWhere = "WHERE ds.name LIKE '#{@name}';"

query = sqlSelect + sqlWhere


report = Nexpose::AdhocReportConfig.new(nil, 'sql')
report.add_filter('version', '1.2.1')
report.add_filter('query', query)
report.add_filter('group', 1)
report_output = report.generate(nsc)
csv_output = CSV.parse(report_output.chomp, { :headers => :first_row })
CSV.open("adhoc#{@name}Report.csv", 'w') do |csv_file|
    csv_file << csv_output.headers
    csv_output.each do |row|
        csv_file << row
    end
end

puts 'Report completed and saved, deleting site'
site.delete(nsc) 

puts 'Site deleted, logging out'
exit
