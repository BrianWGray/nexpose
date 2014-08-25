#!/usr/bin/env ruby
# Brian W. Gray 08/08/2014


# Queries heavily draw from:
# https://community.rapid7.com/message/11358#11358
# https://community.rapid7.com/docs/DOC-2612
#



require 'yaml'
require 'nexpose'
require 'csv'

# Default Values

config = YAML.load_file("conf/nexpose.yaml") # From file

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]


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


puts "Example: Enter \"23\" if you want to query for port 23."
prompt = 'Please enter a port number to query for: '
print prompt
#Limiting character count to 32
UserInput = STDIN.gets(32).chomp()



sqlSelect = "SELECT da.ip_address, das.port, dp.name AS protocol, ds.name AS service, dsf.version AS service_version, dsf.name AS service_name, da.host_name, dos.name AS OS, dos.version AS os_version
FROM dim_asset_service das
JOIN dim_service ds USING (service_id)
JOIN dim_protocol dp USING (protocol_id)
JOIN dim_asset da USING (asset_id)
JOIN dim_operating_system dos USING (operating_system_id)
JOIN dim_service_fingerprint dsf USING (service_fingerprint_id) "

sqlWhere = "Where das.port = #{UserInput}"

sqlOrderBy = " ORDER BY da.ip_address, das.port;"

query = sqlSelect + sqlWhere + sqlOrderBy


report = Nexpose::AdhocReportConfig.new(nil, 'sql')
report.add_filter('version', '1.2.1')
report.add_filter('query', query)
report_output = report.generate(nsc,18000) # Timeout for report generation is currently set at ~30 minutes
csv_output = CSV.parse(report_output.chomp, { :headers => :first_row })
CSV.open("openPort_#{UserInput}_export.csv", 'w') do |csv_file|
    csv_file << csv_output.headers
    csv_output.each do |row|
        csv_file << row
    end
end

puts "CSV export completed and saved to ./OpenPort_#{UserInput}_export.csv."

exit
