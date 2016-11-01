#!/usr/bin/env ruby
# Brian W. Gray 11/12/2014

require 'yaml'
require 'csv'
require 'nexpose'
require 'pp'

include Nexpose

# Default Values
# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]

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



begin

    templates = nsc.list_scan_templates
    
    templates.each do |templateInfo|
        puts "TemplateID: #{templateInfo.id}, TemplateName: #{templateInfo.name}"
        scanTemplateInfo = Nexpose::ScanTemplate.load(nsc,"#{templateInfo.id}")
    
        pp scanTemplateInfo
    end
end

exit
