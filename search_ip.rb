#!/usr/bin/env ruby
# Brian W. Gray
# 08.22.2016

# Example on querying whether an ip exists in a specified site.

# Script performs the following tasks
## 1.) Retrieve address entries for each site.
## 2.) check the asset array for a specified address.
## 3.) Print true or false whether the ip provided is within the site provided

require 'yaml'
require 'nexpose'
require 'ipaddr'
include Nexpose 

# Default Values

config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]

siteId = 0

nsc = Nexpose::Connection.new(@host, @userid, @password, @port)

begin
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end

at_exit { nsc.logout }


def convert_ip_range(start_ip, end_ip)
    start_ip = IPAddr.new(start_ip)
    end_ip   = IPAddr.new(end_ip)
    
    (start_ip..end_ip).map(&:to_s)
end

def search_ip(assetList, ip)
    @assetList, @ip = assetList, ip
    @assetList.include?(@ip)
end

def assets (siteAddresses)
	@siteAddresses = siteAddresses
    @assetList = [] # => list of ipaddresses in a site

	@siteAddresses.each do |asset|
		if asset.respond_to? :from
               		if asset.to != nil
                    		startRange = "#{asset.from}" if asset.to
                    		endRange = "#{asset.to}"
                    		@assetList << convert_ip_range(startRange.to_s, endRange.to_s)
                	else
                    		@assetList << asset
                	end
        end
	end
    return @assetList.flatten
end

#TODO: Add validation for whether a site exists prior to attempting to access it
site = Nexpose::Site.load(nsc, siteId) # => Load Nexpose Site Data
assetList = assets(site.included_addresses) # => detonate all site assets into an array


# Accept arguments for the numerical site ID and an address to search for.
if ARGV.length < 2
    # If no argument is passed print usage and exit
    puts "usage: #{__FILE__} siteId# Address"
    exit
else
    siteId, findIp = ARGV[0], ARGV[1]
end

# provide a detonated ip list and search the array for a specified ip address value
# if the address is within the array true is returned else false returned.
if search_ip(assetList, findIp) == true; puts "true"; else puts "false"; end



exit
