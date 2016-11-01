#!/usr/bin/env ruby
# Brian W. Gray
# 09.08.2014

## Script lists available application backup.

require 'yaml'
require 'nexpose'

include Nexpose

# Default Values

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

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
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end

at_exit { nsc.logout }


# Check scan activity wait until there are no scans running
listBackups = nsc.list_backups
if listBackups.any?
    puts "List of available Backups on #{@host} :\r\n"
    listBackups.each do |backupList|
        puts "Name: #{backupList.name} Description: #{backupList.description} size: #{backupList.size} Date : #{backupList.date}"
    end

end

exit
