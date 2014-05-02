#!/usr/bin/env ruby

# Date Created: 04.30.2014
# Written by: BrianWGray

require 'nexpose'
require 'optparse'
require 'highline/import'

include Nexpose

# Default Values

@host = 'localhost'
@port = '3780'
@user = 'nxadmin'

OptionParser.new do |opts|
  opts.banner = "Usage: #{File::basename($0)} [Asset Group ID number] [options]"
  opts.separator ''
  opts.separator 'This script will re-launch scans against a provided asset group id number.'
  opts.separator ''
  opts.separator 'Note that this script will always prompt for a connection password.'
  opts.separator ''
  opts.separator 'Options:'
  opts.on('-h', '--host [HOST]', 'IP or hostname of Nexpose console. Default: localhost') { |host| @host = host }
  opts.on('-p', '--port [PORT]', Integer, 'Port of Nexpose console. Default: 3780') { |port| @port = port }
  opts.on('-u', '--user [USER]', 'Username to connect to Nexpose with. Default: nxadmin') { |user| @user = user }
  opts.on_tail('--help', 'Print this help message.') { puts opts; exit }
end.parse!

unless ARGV[0]
  $stderr.puts 'Asset Group ID Required.'
  exit(1)
end

@agid = ARGV[0]

def get_password(prompt = 'Password: ')
  ask(prompt) { |query| query.echo = false }
end

puts "logging into #{@host} as #{@user} on port #{@port}"
@password = get_password


nsc = Nexpose::Connection.new(@host, @user, @password, @port)
puts 'Nexpose login initiated'
nsc.login

puts 'Nexpose login successful'

puts "Initializing scans for Asset Group ID #{@agid}"
group = AssetGroup.load(nsc, @agid)
scans = group.rescan_assets(nsc)

puts 'Scan jobs submitted'

at_exit { nsc.logout }
puts 'Logging out'
exit
