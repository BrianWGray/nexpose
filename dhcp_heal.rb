#!/usr/bin/env ruby

# Date Created: 11.16.2017
# Written by: BrianWGray

# Written for
# DCHP dynamic connectors are unstable.
# Currently running in an hourly cronjob

## Script performs the following tasks
## 1.) List DHCP dynamic connections
## 2.) Check connection status
## 3.) Heal failed connections
## 4.) TODO: Re-Evaluate connection status for confirmation

require 'yaml'
require 'nexpose'
require 'pp'
include Nexpose

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

host = config["hostname"]
userid = config["username"]
password = config["passwordkey"]
port = config["port"]

nsc = Nexpose::Connection.new(host, userid, password, port)

begin
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end
at_exit { nsc.logout }

connectionList = nsc.list_discovery_connections

connectionList.each do | dynCon |
	puts("#{dynCon.id} : #{dynCon.name} Status: #{dynCon.status}") 

    # Hardcode name of the dhcp connection to check until I determine a cleaner way
	if((!dynCon.name.include?("Sonar")) && (dynCon.name.include?("DHCP")) && (dynCon.status.include?("Not Connected"))) 
        dynCon.type = 'DHCP_SERVICE'
        dynCon.collection_method = 'SYSLOG'
        dynCon.event_source = 'INFOBLOX_TRINZIC'
        dynCon.engine_id = 14

        #pp(dynCon)
        puts "Correcting dynamic connection issue on ID #{dynCon.id} : #{dynCon.name}"
	end
end

exit