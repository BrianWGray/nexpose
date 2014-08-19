#!/usr/bin/env ruby
# Brian W. Gray
# 07.14.2014

## Script runs the following database maintenance tasks
## 1.) Clean up database - Removes any unnecessary data from the database
## 2.) Compress database tables - Compresses the database tables and reclaims unused, allocated space.
## 3.) Reindex database - Drops and recreates the database indexes for improved performance.

require 'yaml'       # Add support for external configurations via yaml file.
require 'net/http'   # Used to check whether the nexpose service is available.
require 'nexpose'    # Add nexpose-client gem to interact with Nexpose.

include Nexpose

# Default Values

config = YAML.load_file("conf/nexpose.yaml") # From file

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]
@serviceTimeout = config["servicetimeout"]


def checkService()
    tryAgain = 0
    
    begin
        begin
            path = '/login.html'  # Check to see if we may login or if we are re-directed to the maintenance login page.
        
            http = Net::HTTP.new(@host,@port)
            http.read_timeout = 1
            http.use_ssl = true
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE
            response = nil
        
            http.start{|http|
                request = Net::HTTP::Get.new(path)
                response = http.request(request)
            }
        
        rescue Exception   # should really list all the possible http exceptions
                puts "Attempt: #{tryAgain} Service Unavailable"
                sleep (30)
                retry if (tryAgain += 1) < @serviceTimeout
        end
        
        response.code
        if response.code == "200" # Check the status code anything other than 200 indicates the service is not ready.
            puts "Attempt: #{tryAgain} #{response.code} The Nexpose Service appears to be up and functional"
            tryAgain = @serviceTimeout
        else
            puts "Attempt: #{tryAgain} #{response.code} #{response.message} The Service is not yet fully initialized"
            tryAgain += 1
            sleep(30)
        end
    end while tryAgain < @serviceTimeout
    
    if (response.code != "200")
        puts "The service was never determined to be available. Action Timed Out"
        exit
    end
end


nsc = Nexpose::Connection.new(@host, @userid, @password, @port)


begin
    checkService()
    puts 'logging into Nexpose'
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

# Start database maintenance
if active_scans.empty?
    platform_independent = true
    puts "Initiating Database Maintenance tasks"
    nsc.db_maintenance(1,1,1)
    else
    
end


puts 'Logging out'
exit