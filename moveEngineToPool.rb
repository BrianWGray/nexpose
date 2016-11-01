#!/usr/bin/env ruby
# Brian W. Gray
# 04.09.2015

## Script performs the following tasks
## 1.) Stop all scans assigned sites assigned to a specified scan engine.
## 2.) Stop all scans running on the engine to be removed.
## 3.) Assign the listed sites from one scan engine to a new scan engine.
## 4.) TODO: efficiency improvements.

## This script was primarily meant to be used for moving sites from engines to scan pools.


require 'yaml'
require 'nexpose'

include Nexpose


engineID = 3 # engine id to move from
newEngineID = 6 # engine id to move to

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

engineInfo = Nexpose::Engine.load(nsc, engineID)

engineInfo.sites.each do |engineSites|
    begin
        puts "Moving Site ID: #{engineSites.id}, Site Name: #{engineSites.name} from EngineID: #{engineID} to EngineID #{newEngineID}"
        
        begin
            siteModify = Nexpose::Site.load(nsc,engineSites.id)
            siteModify.engine_id = newEngineID
            siteModify.save(nsc)
           
        rescue ::Nexpose::APIError => err
            puts "Error during site modify function: #{err.reason}"
        end
    
    rescue ::Nexpose::APIError => err
        puts "Error modifying Site ID: #{engineSites.id}, Site Name: #{engineSites.name}'s scan engine: #{err.reason}"
    end
end

exit
