#!/usr/bin/env ruby
# Brian W. Gray
# 11.10.2014

## Script performs the following tasks
## 1.) Retrieve a list of paused scans from a console.
## 2.) Iteratively stop scans that have paused without completing.
## 4.) TODO: Massive code cleanup + efficiency improvements.

require 'yaml'
require 'nexpose'

include Nexpose

# Default Values
config = YAML.load_file("conf/nexpose.yaml") # From file

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]
@consecutiveCleanupScans = config["cleanupqueue"]
@cleanupWaitTime = config["cleanupwaittime"]
@nexposeAjaxTimeout = config["nexposeajaxtimeout"]

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


## Start loop that will continue until there are no longer any scans that are paused.
begin
    begin
            puts "\r\nRequesting scan status updates from #{@host}\r\n"
            ## Pull data for paused scans - Method suggested by JGreen https://community.rapid7.com/thread/5075 (THANKS!!!)
            pausedScans = DataTable._get_dyn_table(nsc, '/ajax/scans_history.txml').select { |scanHistory| (scanHistory['Status'].include? 'Paused')}
        rescue Exception   # should really list all the possible http exceptions
            puts "Connection issue detected - Retrying in 30 seconds"
            sleep (120)
        retry
    end
    
    ## Loop through paused scans for cleanup.
    pausedScans.each do |scanHistory|
                   
                   scanIDReport = scanHistory['Scan ID']
                   statusReport = scanHistory['Status']
                   discoveredReport = scanHistory['Devices Discovered']
                   puts "Stopping ScanID: #{scanIDReport}, Discovered: #{discoveredReport}  - #{statusReport}"
                   ## Stop the provided scanid.
                   nsc.stop_scan(scanIDReport)
    end

    
## If there are no more paused scans, we can exit.
end while ((pausedScans.count) > 0)

puts "No Paused scans were returned in the request. Exiting"

puts 'Logging out'
exit