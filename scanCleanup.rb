#!/usr/bin/env ruby
# Brian W. Gray
# 09.04.2014

## Script performs the following tasks
## 1.) Retrieve a list of scans from a console.
## 2.) TODO: Iteratively resume scans in batches for scans that have paused due to memory errors.
## 3.) TODO:

require 'yaml'
require 'nexpose'


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

activeScans = nsc.scan_activity()
activeScans.each do |status|
    puts "#{status.scan_id} : #{status.status}"
end

puts 'Logging out'
exit
