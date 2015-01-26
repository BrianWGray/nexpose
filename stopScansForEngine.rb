#!/usr/bin/env ruby
# Brian W. Gray
# 01.26.2015

## Script performs the following tasks
## 1.) Retrieve a list of active scans from a console.
## 2.) Iteratively stop all scans for a specific scan engine id.
## 3.) TODO: Massive code cleanup + efficiency improvements.

require 'yaml'
require 'nexpose'

include Nexpose


engineID = 6 # engine id to stop

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]
@nexposeAjaxTimeout = config["nexposeajaxtimeout"]

nsc = Nexpose::Connection.new(@host, @userid, @password, @port)
begin
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end
at_exit { nsc.logout }

## Pull data for active scans
activeScans = nsc.scan_activity()
# Collect Site info to provide additional information for screen output.
siteInfo = nsc.sites

## Iterate through active scans and stop scans matching the specified engine id.
activeScans.each do |status|
    siteInfoID = status.site_id
    begin
        if status.engine_id == engineID # This should probably just be an include? engine_id = engineID for the array.
            puts "Stopping scanid: #{status.scan_id} on EngineID: #{status.engine_id} for SiteID #{status.site_id} : #{siteInfo[siteInfoID].name}"
            nsc.stop_scan(status.scan_id)
        end
        rescue
        puts "Error stopping scanid #{status.scan_id} on EngineID: #{status.engine_id} for SiteID #{status.site_id} : #{siteInfo[siteInfoID].name} to the stop queue"
    end
end

exit