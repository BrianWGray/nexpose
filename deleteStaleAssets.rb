#!/usr/bin/env ruby
# WhyIsThisOpen
# 03.02.2015

## Script deletes stale assets that are part of a site with a scheduled scan.

require 'yaml'
require 'nexpose'

include Nexpose

# Default Values

config = YAML.load_file("conf/nexpose.yaml") # From file

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]
@staleDays = config["staledays"]

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

# Check scan activity and wait until there are no scans running
begin
    active_scans = nsc.scan_activity
    if active_scans.any?
        puts "Current scan status: #{active_scans.to_s}"
        sleep(15)
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
        puts "No scheduled scans for #{site.name}"
    end
end

# Find assets that have not been scanned in the last @staleDays.  
old_assets = nsc.filter(Search::Field::SCAN_DATE, Search::Operator::EARLIER_THAN, @staleDays)  

# Iterate through the assets and delete those in sites with schedules.
old_assets.each do |device|
    if scheduledSites.include?(device.site_id)
        puts "Deleting #{device.ip} [ID: #{device.id}] Site: #{device.site_id}"
        nsc.delete_device(device.id)    
    end
end

puts 'Logging out'
exit

