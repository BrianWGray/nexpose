#!/usr/bin/env ruby
# Brian W. Gray
# 09.04.2014

## Script performs the following tasks
## 1.) Retrieve a list of paused scans from a console.
## 2.) Retrieve a list of active scans from a console.
## 3.) Sort paused scans from least number of discovered assets to most
## 4.) Iteratively resume scans in batches for scans that have paused without completing.
## 5.) TODO: Massive code cleanup + efficiency improvements.

## Major code changes as of 11.21.2014 - BWG
# Rearranged output information to a more logical order.
# Screen output now includes additional information about the scan in the screen output.
# Worked on Bug reduction.
#   - Fixed connection error information.
#   - Fixed issue with sessions being invalidating and never being recreated.
#   - Fixed yaml relative path issues with running the script from outside of its directory.
#   - Some code clean up.


require 'yaml'
require 'nexpose'

include Nexpose

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]
@consecutiveCleanupScans = config["cleanupqueue"]
@cleanupWaitTime = config["cleanupwaittime"]
@nexposeAjaxTimeout = config["nexposeajaxtimeout"]

fillQueue = 0


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


## Start loop that will continue until there are no longer any scans paused or actively running.
begin
    begin
            puts "\r\nRequesting scan status updates from #{@host}\r\n"
            ## Pull data for paused scans - Method suggested by JGreen https://community.rapid7.com/thread/5075 (THANKS!!!)
            pausedScans = DataTable._get_dyn_table(nsc, '/ajax/scans_history.txml').select { |scanHistory| (scanHistory['Status'].include? 'Paused')}
            ## Pull data for active scans
            activeScans = nsc.scan_activity()
    
        rescue Exception   # should really list all the possible http exceptions
            puts "Connection issue detected - Retrying in #{@cleanupWaitTime} seconds)"
            sleep (@cleanupWaitTime)
            begin # This is a less than ideal bandaid to make sure there is a valid session.
                nsc.login
                rescue ::Nexpose::APIError => err
                $stderr.puts("Connection failed: #{err.reason}")
                exit(1)
            end
        retry
    end
    
    # Collect Site info to provide additional information for screen output.
    siteInfo = nsc.sites
    
    ## Attempting some basic prioritization to complete lower asset count scans first.
    ## Perform a destructive sort of the pausedScans array based on the number of discovered assets.
    pausedScans.sort! { |a,b| a['Devices Discovered'].to_i <=> b['Devices Discovered'].to_i }
    
    ## List all of the paused scans to stdout.
    puts "\r\n-- Paused Scans Detected : #{pausedScans.count}  --\r\n"
    pausedScans.each do |scanHistory|
        siteInfoID = scanHistory['Site ID'].to_i
        puts "ScanID: #{scanHistory['Scan ID']}, Assets: #{scanHistory['Devices Discovered']}, SiteID: #{siteInfoID} - #{siteInfo[siteInfoID].name}, #{scanHistory['Status']}"
    end
    puts "-- Paused Scans Detected : #{pausedScans.count}  --\r\n"


    puts "\r\n -- Queue Size: #{@consecutiveCleanupScans} -- \r\n"
    
    ## Output a list of active scans in the scan queue.
    activeScans.each do |status|
        siteInfoID = status.site_id
        puts "ScanID: #{status.scan_id}, Assets: #{status.nodes.live}, SiteID: #{status.site_id} - #{siteInfo[siteInfoID].name}, Status:#{status.status}, EngineID:#{status.engine_id}, StartTime:#{status.start_time}"
    end
    
    ## Check to see if there are any slots open in the cleanup queue and that there are still scans to resume.
    if ((activeScans.count < @consecutiveCleanupScans.to_i) and (pausedScans.count > 0))
       
       ## Determine how many slots are left in the cleanup queue to use.
       fillQueue = ((@consecutiveCleanupScans - activeScans.count)-1)
       ## Loop through just enough paused scans to fill the open slots in the cleanup queue.
       pausedScans[0..fillQueue.to_i].each do |scanHistory|
           siteInfoID = scanHistory['Site ID'].to_i
           puts "Resuming ScanID: #{scanHistory['Scan ID']}, Assets: #{scanHistory['Devices Discovered']}, SiteID: #{siteInfoID} - #{siteInfo[siteInfoID].name}, Status: #{scanHistory['Status']}"
           ## Resume the provided scanid.
           nsc.resume_scan(scanHistory['Scan ID'])
       end
       
    end
    
    if ((pausedScans.count + activeScans.count) > 0)
        ## Wait between checks so that the scans have time to run.
        sleep(@cleanupWaitTime)
    end
    
## If there are no more paused scans and the active scans have all completed without failing we can exit.
end while ((pausedScans.count + activeScans.count) > 0)

puts 'Logging out'
exit