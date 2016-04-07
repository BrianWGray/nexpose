#!/usr/bin/env ruby
# Brian W. Gray
# 04.07.2016

# Put together to try and determine a good way to answer question https://community.rapid7.com/thread/5394

# Script performs the following tasks
## 1.) Retrieve a list of available sites from a console.
## 2.) Retrieve address entries for each site.
## 3.) Convert address ranges to ip address counts
## 4.) Provide a total of scanned addresses per site.
## 5.) Provide a count of live nodes recorded in the last scan for each site
## 6.) Provide a total count of discoverable addresses for all sites combined.
## 7.) Provide a total count of active nodes for all sites combined.


require 'yaml'
require 'nexpose'
require 'ipaddr'
require 'pp'
include Nexpose 

# Default Values

config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]

assetCounter = 0
@liveAssetCounter = 0
@liveNodes = 0

defaultFile = 'AssetUsage_' + DateTime.now.strftime('%Y-%m-%d--%H%M') + '.csv'

nsc = Nexpose::Connection.new(@host, @userid, @password, @port)
#puts 'logging into Nexpose'


begin
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end

at_exit { nsc.logout }

site = nsc.list_sites
case site.length
    when 0
	puts("There are currently no active sites on this NeXpose instance")
end


def convert_ip_range(start_ip, end_ip)
    start_ip = IPAddr.new(start_ip)
    end_ip   = IPAddr.new(end_ip)
    
    (start_ip..end_ip).map(&:to_s)
end

File.open(defaultFile, 'w') do |file|

file.puts "\"Site\",Discovery Count,Nodes detected in last scan"
puts "Site, Discovery Count, Nodes detected in last scan"

begin
	site.each do |site|
		site = Nexpose::Site.load(nsc, site.id)
		# puts "Getting defined assets for #{site.name}"

        # pp site ## DEBUG

		site.included_addresses.each do |asset|
            @siteCount = 0
            @liveNodes = 0
			currentCount = 0

            if asset.respond_to? :from
                
                if asset.to != nil
                    startRange = "#{asset.from}" if asset.to
                    endRange = "#{asset.to}"
                    currentCount = convert_ip_range(startRange.to_s, endRange.to_s).count
                else
                    currentCount = 1
                end                                
			end
                assetCounter += currentCount
                @siteCount += currentCount
		end

        latest = nsc.last_scan(site.id)

        if latest
           @liveNodes += latest.nodes.live
           # @liveNodes += latest.nodes.dead
           # @liveNodes += latest.nodes.filtered
           # @liveNodes += latest.nodes.unresolved
           # @liveNodes += latest.nodes.other
        end

        @liveAssetCounter += @liveNodes 
        file.puts "\"#{site.name}\",#{@siteCount},#{@liveNodes}"
        puts "\"#{site.name}\", #{@siteCount}, #{@liveNodes}"
    end
end

file.puts "\"Total tally of discoverable addresses for all sites:\",#{assetCounter}"
puts "\"Total tally of discoverable addresses for all sites:\",#{assetCounter}"
file.puts "\"Total tally of live nodes for all sites:\",#{@liveAssetCounter}"
puts "\"Total tally of live nodes for all sites:\",#{@liveAssetCounter}"
end

puts 'Logging out'
exit
