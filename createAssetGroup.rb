#!/usr/bin/env ruby

# Date Created: 04.30.2014
# Written by: BrianWGray

## Script performs the following tasks
## 1.) Read addresses from text file
## 2.) De-duplicate addresses
## 3.) Create new asset group
## 4.) Add addresses to the created asset group

require 'yaml'
require 'nexpose'
require 'optparse'
require 'highline/import'

# Default Values

config = YAML.load_file("conf/nexpose.yaml") # From file

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]

@name = @desc = nil

OptionParser.new do |opts|
  opts.banner = "Usage: #{File::basename($0)} [options]"
  opts.separator ''
  opts.separator 'Create an asset group based upon an input file, one IP per line.'
  opts.separator ''
  opts.separator 'By default, it uses the name of the file as the name of the asset group and does not check if name exists.'
  opts.separator 'If multiple sites include the same address, it is non-deterministic which asset it will choose.'
  opts.separator ''
  opts.separator 'Options:'
  opts.on('-n', '--name [NAME]', 'Name to use for new asset group. Must not already exist.') { |name| @name = name }
  opts.on('-d', '--desc [DESCRIPTION]', 'Description to use for new asset group.') { |desc| @desc = desc }
  opts.on('-x', '--debug', 'Report duplicate IP addresses to STDERR.') { |debug| @debug = debug }
  opts.on_tail('--help', 'Print this help message.') { puts opts; exit }
end.parse!

# Any arguments after flags can be grabbed now."
unless ARGV[0]
  $stderr.puts 'Input file is required.'
  exit(1)
end
file = ARGV[0]
@name = File.basename(file, File.extname(file)) unless @name

# This will fail if the file cannot be read.
ips = File.read(file).split.uniq

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

# Create a map of all assets by IP to make them quicker to find.
all_assets = nsc.assets.reduce({}) do |hash, dev|
  $stderr.puts("Duplicate asset: #{dev.address}") if @debug and hash.member? dev.address 
  hash[dev.address] = dev
  hash
end

# Drop the connection, in case group creation takes too long.
nsc.logout

group = Nexpose::AssetGroup.new(@name, @desc)

ips.each do |ip|
  if all_assets.member? ip
    group.devices << all_assets[ip]
  elsif @debug
    $stderr.puts("No asset with IP #{ip} found.")
  end
end

nsc.login
group.save(nsc)
puts "Group '#{@name}' saved with #{group.devices.size} assets."

exit