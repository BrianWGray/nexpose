#!/usr/bin/env ruby
# Brian W. Gray
# 01.22.2015

## Script performs the following tasks
## 1.) Retrieve a list of paused scans from a console.
## 2.) Retrieve a list of active scans from a console.
## 3.) Sort paused scans from least number of discovered assets to most
## 4.) Iteratively resume scans in batches for scans that have paused without completing.
## 5.)
## 6.) TODO: Massive code cleanup + efficiency improvements.

## Major code changes as of 11.21.2014 - BWG
# Rearranged output information to a more logical order.
# Screen output now includes additional information about the scan in the screen output.
# Worked on Bug reduction.
#   - Fixed connection error information.
#   - Fixed issue with sessions being invalidating and never being recreated.
#   - Fixed yaml relative path issues with running the script from outside of its directory.
#   - Some code clean up.

## Update - 02.23.2016 - BWG
# Changed how paused scans are pulled basd on https://community.rapid7.com/thread/7904
## Update - 04.25.2017 - BWG
# Code refactor

#require 'pp'
require 'yaml'
require 'nexpose'
require 'time'
include Nexpose

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]
@cleanupWaitTime = config["cleanupwaittime"]
@nexposeAjaxTimeout = config["nexposeajaxtimeout"]

nsc = Nexpose::Connection.new(@host, @userid, @password, @port)

begin
    nsc.login
rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
    raise
end
at_exit { nsc.logout }

=begin
## Initialize connection timeout values.
module Nexpose
  class APIRequest
    include XMLUtils
    # Execute an API request (5th param used for gem version 5.3.0+)
    def self.execute(url, req, api_version='2.0', options = {}, trust_store = nil)
      options = {timeout: 6000000}
      obj = self.new(req.to_s, url, api_version, trust_store)
      obj.execute(options)
      return obj
    end
  end

  module AJAX
    def self.https(nsc, timeout = nil)
      http = Net::HTTP.new(nsc.host, nsc.port)
      http.use_ssl = true
      # changes for gem version 5.3.0+
      if nsc.trust_store.nil?
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      else
        http.cert_store = nsc.trust_store
      end
      http.read_timeout = @nexposeAjaxTimeout
      http.open_timeout = @nexposeAjaxTimeout
      http.continue_timeout = @nexposeAjaxTimeout
      http
    end
  end
end
=end

def scan_status(nsc, config)
    begin
        puts "\r\nRequesting scan status updates from #{@host}\r\n"
        ## Pull data for paused scans
        pausedScans = nsc.paused_scans
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
           raise
        end
    retry
    end
    scans = {:activeScans => activeScans, :pausedScans => pausedScans}
    return scans
end

def list_paused_scans(nsc, config, scans)
    ## Attempting some basic prioritization to complete lower asset count scans first.
    ## Perform a destructive sort of the pausedScans array based on the number of discovered assets.
    scans[:pausedScans].sort! { |a,b| a.assets.to_i <=> b.assets.to_i }
    # Collect Site info to provide additional information for screen output.
    siteInfo = nsc.sites
    ## List all of the paused scans to stdout.
    puts "\r\n-- Paused Scans Detected : #{scans[:pausedScans].count}  --\r\n"
    scans[:pausedScans].each do |scanHistory|
        siteInfoID = scanHistory.site_id.to_i
        siteDetail = Site.load(nsc, siteInfoID)
        ## scanDetail = ScanSummary.select{ |scanInfo| (scanInfo['scan_id'].include? scanHistory.id.to_i)}
        begin
            puts "ScanID: #{scanHistory.id}, Assets: #{scanHistory.assets}, ScanTemplate: #{siteDetail.scan_template_id}, SiteID: #{siteInfoID} - #{siteDetail.name}, #{scanHistory.status}"
        rescue
            #raise
        end
    end
    puts "\r\n\r\n"
end

def list_active_scans(nsc, config, scans)
    hostCount = 0
    puts "-- Active Scans Detected : #{scans[:activeScans].count} | Queue Size: #{config["cleanupqueue"]}. --\r\n"
    ## Output a list of active scans in the scan queue.
    scans[:activeScans].each do |status|
        siteInfoID = status.site_id
        siteDetail = Site.load(nsc, siteInfoID)
        ## scanDetail = ScanSummary.select{ |scanInfo| (scanInfo['scan_id'].include? scanHistory['Scan ID'].to_i)}
        begin
            Scan
            puts "ScanID: #{status.scan_id}, Assets: #{status.nodes.live}, ScanTemplate: #{siteDetail.scan_template_id}, SiteID: #{status.site_id} - #{siteDetail.name}, Status:#{status.status}, EngineID:#{status.engine_id}, StartTime:#{status.start_time}"
            hostCount += status.nodes.live
        rescue
            #raise
        end    
    end
    return hostCount
end

def resume_scans(nsc, config, scans)
    fillQueue = hostCount = 0
    ## Check to see if there are any slots open in the cleanup queue and that there are still scans to resume.
    if ((scans[:activeScans].count < config["cleanupqueue"]) and (scans[:pausedScans].count > 0))
        ## Determine how many slots are left in the cleanup queue to use.
        fillQueue = ((config["cleanupqueue"] - scans[:activeScans].count) -1)
        ## Loop through just enough paused scans to fill the open slots in the cleanup queue.
        scans[:pausedScans][0..fillQueue.to_i].each do |scanHistory|
            siteInfoID = scanHistory.site_id.to_i
            siteDetail = Site.load(nsc, siteInfoID)
            begin
                hostCount += scanHistory.assets.to_i # Count the number of hosts being scanned.
                puts "Resuming ScanID: #{scanHistory.id}, Assets: #{scanHistory.assets}, ScanTemplate: #{siteDetail.scan_template_id}, SiteID: #{siteInfoID} - #{siteDetail.name}, Status: #{scanHistory.status}"
            rescue
                raise
            end
            
            begin
                # Resume the provided scanid.
                nsc.resume_scan(scanHistory.id)
            rescue
            end
        end
    end
    return hostCount
end

## Start loop that will continue until there are no longer any scans paused or actively running.
begin
    scans = scan_status(nsc, config)
    list_paused_scans(nsc, config, scans)
    hostCount = 0 # Initialize hostCount.
    hostCount += list_active_scans(nsc, config, scans)
    hostCount += resume_scans(nsc, config, scans)
    puts "Total expected Active hosts being scanned: #{hostCount} - #{Time.now}\r\n\r\nNext Run time: #{Time.now + @cleanupWaitTime}\r\n\r\n"
    if ((scans[:pausedScans].count + scans[:activeScans].count) > 0)
        ## Wait between checks so that the scans have time to run.
        sleep(@cleanupWaitTime)
    end    
## If there are no more paused scans and the active scans have all completed without failing we can exit.
end while ((scans[:pausedScans].count + scans[:activeScans].count) > 0)

puts 'Logging out'
exit
