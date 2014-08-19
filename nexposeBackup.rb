#!/usr/bin/env ruby
# Brian W. Gray
# 07.14.2014

## Script generates a Platform Independant application backup.

require 'yaml'
require 'nexpose'

include Nexpose

# Default Values

config = YAML.load_file("conf/nexpose.yaml") # From file

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]


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

begin
    # Check scan activity wait until there are no scans running
    active_scans = nsc.scan_activity
	if active_scans.any?
        puts "Current scan status: #{active_scans.to_s}"
        sleep(15)
    end
end while active_scans.any?

time = Time.new
backupDescription = time.strftime("%Y%m%d")+"_PI_Weekly"

# Base backup code use from https://community.rapid7.com/thread/4687
# Start the backup
if active_scans.empty?
    platform_independent = true
    puts "Initiating Platform Independent backup to local disk"
    nsc.backup(platform_independent, backupDescription)
else

end


puts 'Logging out'
exit
