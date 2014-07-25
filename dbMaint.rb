#!/usr/bin/env ruby
# Brian W. Gray
# 07.14.2014

## Script runs the following database maintenance tasks
## 1.) Clean up database - Removes any unnecessary data from the database
## 2.) Compress database tables - Compresses the database tables and reclaims unused, allocated space.
## 3.) Reindex database - Drops and recreates the database indexes for improved performance.

require 'yaml'
require 'nexpose'

include Nexpose

# Default Values

config = YAML.load_file("conf/nexpose.yaml") # From file

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]


nsc = Nexpose::Connection.new(@host, @userid, @password, @port))
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
end while active_scans.to_s.empty?

# Base backup code use from https://community.rapid7.com/thread/4687
# Start the backup
if active_scans.empty?
    platform_independent = true
    puts "Initiating Database Maintenance tasks"
    nsc.db_maintenance(1,1,1)
    else
    
end


puts 'Logging out'
exit
