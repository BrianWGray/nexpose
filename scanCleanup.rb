#!/usr/bin/env ruby
# Brian W. Gray
# 09.04.2014

## Script performs the following tasks
## 1.) Retrieve a list of paused scans from a console.
## 2.) Retrieve a list of active scans from a console.
## 3.) Iteratively resume scans in batches for scans that have paused without completing.
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

fillQueue = 0


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

## Start loop that will continue until there are not longer any scans paused or actively running.
begin
    
    ## Pull data for paused scans - Method suggested by JGreen https://community.rapid7.com/thread/5075 (THANKS!!!)
    pausedScans = DataTable._get_dyn_table(nsc, '/ajax/scans_history.txml').select { |scanHistory| (scanHistory['Status'].include? 'Paused')}
    ## Pull data for active scans
    activeScans = nsc.scan_activity()
    
    puts "\r\n -- Queue Size: #{@consecutiveCleanupScans} -- \r\n"
    
    
    ## Output a list of active scans in the scan queue.
    activeScans.each do |status|
        
        scanIDActive = status.scan_id
        statusActive = status.status
        
        puts "ScanID: #{scanIDActive} : #{statusActive}"
    end
    
    
    ## Check to see if there are any slots open in the cleanup queue and that there are still scans to resume.
    if ((activeScans.count < @consecutiveCleanupScans.to_i) and (pausedScans.count > 0))
       
       ## Determine how many slots are left in the cleanup queue to use.
       fillQueue = ((@consecutiveCleanupScans - activeScans.count)-1)
       ## Loop through just enough paused scans to fill the open slots in the cleanup queue.
       pausedScans[0..fillQueue.to_i].each do |scanHistory|
                   
                   scanIDReport = scanHistory['Scan ID']
                   statusReport = scanHistory['Status']
                   discoveredReport = scanHistory['Devices Discovered']
                   puts "Resuming ScanID: #{scanIDReport}, Discovered: #{discoveredReport}  - #{statusReport}"
                   ## Resume the provided scanid.
                   nsc.resume_scan(scanIDReport)
       end
       
    end
    
    ## List all of the remaining paused scans that still need to be resumed.
    puts "\r\n-- Paused Scans Remaining : #{pausedScans.count}  --\r\n"
        pausedScans.each do |scanHistory|
            
            scanIDReport = scanHistory['Scan ID']
            statusReport = scanHistory['Status']
            discoveredReport = scanHistory['Devices Discovered']
            
            puts "ScanID: #{scanIDReport}, Discovered: #{discoveredReport}  - #{statusReport}"
            
        end
    
    ## Wait between checks so that the scans have time to run.
    sleep(@cleanupWaitTime)
    
## If there are no more paused scans and the active scans have all completed without failing we can exit. 
end while ((pausedScans.count + activeScans.count) > 0)

puts 'Logging out'
exit