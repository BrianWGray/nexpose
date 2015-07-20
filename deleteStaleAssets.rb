#!/usr/bin/env ruby
# WhyIsThisOpen
# 03.02.2015

# Fixed yaml relative path issues with running the script from outside of its directory. - BrianWGray 07.20.2015
# Fixed error output typo. - BrianWGray 07.20.2015
# Slapped in some basic output formatting. - BrianWGray 07.20.2015

## Script deletes stale assets that are part of a site with a scheduled scan.

require 'yaml'
require 'nexpose'
require 'pp'

include Nexpose

# Default Values

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]
@staleDays = config["staledays"]
@cleanupWaitTime = config["cleanupwaittime"]

nsc = Nexpose::Connection.new(@host, @userid, @password, @port)
puts 'logging into Nexpose'

begin
    nsc.login
rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end

puts 'logged into Nexpose'
at_exit { nsc.logout }

# Check scan activity and wait until there are no scans running
begin
    active_scans = nsc.scan_activity
    if active_scans.any?
        puts "Active Scans:"
        ## Pull data for active scans
        activeScans = nsc.scan_activity()
        ## Output a list of active scans in the scan queue.
        activeScans.each do |status|
            siteInfoID = status.site_id
            siteDetail = Site.load(nsc, siteInfoID)
            begin
                Scan
                puts "ScanID: #{status.scan_id}, Assets: #{status.nodes.live}, ScanTemplate: #{siteDetail.scan_template_id}, SiteID: #{status.site_id} - #{siteDetail.name}, Status:#{status.status}, EngineID:#{status.engine_id}, StartTime:#{status.start_time}"
                rescue
                raise
            end
            
        end
        puts "Checking for scans again in #{@cleanupWaitTime} seconds."
        sleep(@cleanupWaitTime)
    end
end while active_scans.any?

# Determine which sites are being scanned on a schedule
scheduledSites = Array.new
sites = nsc.list_sites
sites.each do |site|
    site = Nexpose::Site.load(nsc, site.id)
    if site.schedules.any?
        scheduledSites << site.id
    else
        puts "No scheduled scans for SiteID: #{site.id} SiteName: #{site.name}"
    end
end

# Find assets that have not been scanned in the last @staleDays.  
old_assets = nsc.filter(Search::Field::SCAN_DATE, Search::Operator::EARLIER_THAN, @staleDays)  

# Iterate through the assets and delete those in sites with schedules.
old_assets.each do |device|
    if scheduledSites.include?(device.site_id)
        puts "Deleting #{device.ip} [ID: #{device.id}] Site: #{device.site_id} Last Scanned: #{device.last_scan}"
        nsc.delete_device(device.id)
    end
end

puts 'Logging out'
exit

