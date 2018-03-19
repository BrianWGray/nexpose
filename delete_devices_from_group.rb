#!/usr/bin/env ruby
# 03.19.2018

# Script Purpose
## Purge assets listed within a specified group ID.

## written as an example for https://kb.help.rapid7.com/discuss/5aaabb3e311eea001e60e862


require 'yaml'
require 'nexpose'

include Nexpose

# Default Values
# Group ID to purge assets from
groupID = 53

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]
@staleDays = config["staledays"]
@cleanupWaitTime = config["cleanupwaittime"]

nsc = Nexpose::Connection.new(@host, @userid, @password, @port)

begin
    nsc.login
rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end

at_exit { nsc.logout}

# load the specified asset group to purge and iterate through devices
assetGroup = Nexpose::AssetGroup.load(nsc, groupID)

assetGroup.assets.each do |device|
    puts "Deleting #{device.address} [Device ID: #{device.id}] Site ID: #{device.site_id} Risk Score: #{device.risk_score}"
    nsc.delete_device(device.id)
end


