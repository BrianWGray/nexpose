#!/usr/bin/env ruby
# Brian W. Gray 11/12/2014

require 'yaml'
require 'nexpose'
require 'csv'

# Default Values

config = YAML.load_file("conf/nexpose.yaml") # From file

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]

tagPrefix = "notify"

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


# Query to pull all available #{tagPrefix} tags
sqlSelect = "SELECT tag_name FROM dim_tag "
sqlWhere = "WHERE tag_type ILIKE 'CUSTOM' AND tag_name ILIKE '#{tagPrefix}%';"

query = sqlSelect + sqlWhere

# Run the query to pull all availale tags begining with #{tagPrefix} set at the begining of the script.
pullTags = Nexpose::AdhocReportConfig.new(nil, 'sql')
pullTags.add_filter('version', '1.2.1')
pullTags.add_filter('query', query)
returnedTags = CSV.parse(pullTags.generate(nsc,18000).chomp, { :headers => :first_row })



# Create Query containing assets with a specific associated tag.
sqlSelect = "
WITH
assets AS (
           SELECT  DISTINCT asset_id, daip.ip_address, host_name, operating_system_id
           FROM dim_asset da
           JOIN dim_asset_ip_address daip USING (asset_id)
           ),
notification_tags AS (
                      SELECT asset_id, tag_name
                      FROM assets
                      JOIN dim_tag_asset USING (asset_id)
                      JOIN dim_tag USING (tag_id)
                      WHERE tag_type = 'CUSTOM'
                      )
SELECT ip_address AS \"IP\", host_name AS \"Host Name\", ds.name AS \"Site\", tag_name AS \"Notification\"
FROM assets
JOIN dim_site_asset USING (asset_id)
JOIN dim_site ds USING (site_id)
LEFT OUTER JOIN notification_tags aot USING (asset_id)  "

# Run a seperate query for each #{returnedTags} Value.
returnedTags.each do |returnedTagRow|
    puts "#{returnedTagRow}"
    sqlWhere = "WHERE tag_name ILIKE '#{returnedTagRow.to_s.strip}'"
    sqlOrderBy = " ORDER BY host_name, ip_address;"

    query = sqlSelect + sqlWhere + sqlOrderBy
    
    report = Nexpose::AdhocReportConfig.new(nil, 'sql')
    report.add_filter('version', '1.2.1')
    report.add_filter('query', query)
    report_output = report.generate(nsc)
    notifyOutput = CSV.parse(report_output.chomp, { :headers => :first_row })
    
    notifyOutput.each do |notification|
        puts "#{notification}"
    end
    
end

exit
