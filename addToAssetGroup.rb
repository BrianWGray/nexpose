#!/usr/bin/env ruby

# Date Created: 07.21.2017
# Written by: BrianWGray

# Borrows heavily from https://github.com/rapid7/nexpose-client/blob/master/scripts/create_asset_group.rb
# Generated for https://community.rapid7.com/thread/7584

## Script performs the following tasks
## 1.) Read addresses from text file
## 2.) De-duplicate addresses
## 3.) Add addresses to the specified asset group id.

require 'yaml'
require 'nexpose'
require 'optparse'

include Nexpose

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]

@groupid = nil

OptionParser.new do |opts|
  opts.banner = "Usage: #{File::basename($0)} addresses.txt [options]"
  opts.separator ''
  opts.separator 'Add assets to an existing asset group based upon an input file, one IP per line.'
  opts.separator ''
  opts.separator 'A group id must be provided.'
  opts.separator 'If multiple sites include the same address, it is non-deterministic which asset it will choose.'
  opts.separator ''
  opts.separator 'Options:'
  opts.on('-i', '--groupid [groupid]', 'Group ID you are adding to. Must already exist.') { |groupid| @groupid = groupid }
  opts.on('-x', '--debug', 'Report duplicate IP addresses to STDERR.') { |debug| @debug = debug }
  opts.on_tail('--help', 'Print this help message.') { puts opts; exit }
end.parse!

# Any arguments after flags can be grabbed now."
unless ARGV[0]
  $stderr.puts 'Input file is required.'
  exit(1)
end
file = ARGV[0]

# This will fail if the file cannot be read.
ips = File.read(file).split.uniq
puts "#{file} loaded."

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

# Create a map of all assets by IP to make them quicker to find.
all_assets = nsc.assets.reduce({}) do |hash, dev|
  $stderr.puts("Duplicate asset: #{dev.address}") if @debug and hash.member? dev.address 
  hash[dev.address] = dev
  hash
end

# Drop the connection, in case group creation takes too long.
# nsc.logout

group = Nexpose::AssetGroup.load(nsc, @groupid)

ips.each do |ip|
    puts "Adding #{ip}"
  if all_assets.member? ip
    group.assets << all_assets[ip]
  elsif @debug
    $stderr.puts("No asset with IP #{ip} found.")
  end
end

# nsc.login
group.save(nsc)
puts "Group '#{group.id}:#{group.name}' saved with #{group.devices.size} assets."

exit