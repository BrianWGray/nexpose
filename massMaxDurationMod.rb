#!/usr/bin/env ruby
# Brian W. Gray
# Original creation date 08.26.2015

## Script performs the following
## 1.) Parses all sites
## 2.) Itterates all available scan schedules for each site
## 3.) Modifies existing max scan duration times to a new default time

## ToDo:)
# 1.) Output a csv log of changes.
# 2.) Accept a csv of sites to change and the values to be used for each specified siteID.

# require gems
require 'yaml'
require 'nexpose'
require 'pp'

include Nexpose

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

# Console login configurations
@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]


# Configure Options for alert template

## Define a new Max Scan Duration time to use for all scans as a default
defaultMaxDuration = 1440

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




nsc = Nexpose::Connection.new(@host, @userid, @password, @port)
begin
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end

puts 'logged into Nexpose'
at_exit { nsc.logout }

puts "Changes may not be made while there are active or paused scans in the console"

begin
    begin
        puts "Requesting scan status updates from #{@host}\r\n"
        ## Pull data for paused scans - Method suggested by JGreen https://community.rapid7.com/thread/5075 (THANKS!!!)
        pausedScans = DataTable._get_dyn_table(nsc, '/data/site/scans/dyntable.xml?printDocType=0&tableID=siteScansTable&activeOnly=true').select { |scanHistory| (scanHistory['Status'].include? 'Paused')}
        
        # Check scan activity wait until there are no scans running or paused
        activeScans = nsc.scan_activity()

        puts "Active Scans: #{activeScans.count}"
        puts "Paused Scans: #{pausedScans.count}"
        
        if (activeScans.any? or pausedScans.any?)
            puts "  Trying again in 60 seconds"
            sleep (60)
        end
        rescue Exception => err
        puts err.message  # should really list all the possible http exceptions
        exit
    end
end while (activeScans.any? or pausedScans.any?)


if activeScans.empty?
    
    # Query the list of sites to work with
    sites = nsc.list_sites
    
    # User notification of changes to be made.
    puts "Maximum scan duration times will be added or modified for every site located on this console."
    
    begin
        # Step through each site in the site listing.
        sites.each do |eachSite|
        begin
            # Load the site configuration to make changes
            site = Nexpose::Site.load(nsc, eachSite.id)
            puts "Evaluating site #{site.name} (id: #{site.id})."
            
            
            begin
                # Check for existing scheduled scans within the site
                if site.schedules.length > 0
                    puts "Number of scheduled scans for #{site.name} (id: #{site.id}): #{site.schedules.length} "
                    
                    site.schedules.each do |scheduledScan|
                        
                        puts "Current max_duration: #{scheduledScan.max_duration}"
                        scheduledScan.max_duration = defaultMaxDuration
                        puts "Modified max_duration: #{scheduledScan.max_duration}"
                        
                        begin
                            
                            # Finalize changes
                            
                            # Save the site configuration with the modified scan schedule value
                            puts "      Saving the new duration value for the scheduled scan."
                            site.save(nsc)
                            puts "Changes saved to site #{site.name} (id:#{site.id})."
                            
                            # Site schedule level error, continue to the next schedule.
                            rescue Exception => err
                            puts err.message
                        end
                        
                        
                    end
                end
            end
            # Site level error, continue to the next site.
            rescue Exception => err
            puts err.message
        end
        
        end
        
        # Global error, this usually exits the loop and terminates.
        rescue Exception => err
        puts err.message
        exit
    end
    
    else
    
end

puts "Updates completed."
exit
