#!/usr/bin/env ruby

# Date Created: 04.30.2014
# Written by: BrianWGray


## Script performs the following tasks
## 1.) Initiates scans for assets located within a specified asset Group ID


require 'yaml'
require 'nexpose'
require 'optparse'
require 'highline/import'
require 'csv'

include Nexpose 

# Default Values

config = YAML.load_file("conf/nexpose.yaml") # From file

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]


OptionParser.new do |opts|
  opts.banner = "Usage: #{File::basename($0)} [Asset Group ID number] [options]"
  opts.separator ''
  opts.separator 'This script will re-launch scans against a provided asset group id number.'
  opts.separator ''
  opts.separator 'Note that this script will always prompt for a connection password.'
  opts.separator ''
  opts.separator 'Options:'
  opts.on_tail('--help', 'Print this help message.') { puts opts; exit }
end.parse!

unless ARGV[0]
  $stderr.puts 'Asset Group ID Required.'
  exit(1)
end

@agid = ARGV[0]

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


puts "Initializing scans for Site ID #{@agid}"
group = AssetGroup.load(nsc, @agid)
scans = group.rescan_assets(nsc)

puts 'Scan jobs submitted'
puts 'Logging out'
exit
