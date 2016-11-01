#!/usr/bin/env ruby
# Brian W. Gray
# 06.09.2015


# List Engines and data associated with each.

require 'yaml'
require 'nexpose'
require 'pp'
include Nexpose



#Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]


begin
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

    nsc.engines.each do |engine|
        engineLoad = Engine.load(nsc,engine.id)
        # pp(engineLoad)
        puts("Engine: #{engine.name}-#{engine.id} Status: #{engine.status}")
        engineLoad.sites.each {|siteData|
            siteInfoID = siteData.id
            siteDetail = Site.load(nsc, siteInfoID)
            # pp(siteDetail)
            siteName = siteDetail.name
            puts "  Site ID: #{siteInfoID} Site Name: #{siteName}"
        }
    end

=begin
    @nsc.list_engine_pools.each do |engine|
        puts(" EnginePool: #{engine.name}-#{engine.id}")
        engineLoad = Engine.load(@nsc,engine.id)
        pp(engineLoad)
    end
=end
 

end
