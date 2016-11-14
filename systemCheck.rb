#!/usr/bin/env ruby

# Brian W. Gray
# 06.08.2015
#
# Purpose: Perform the health checks and perform corrective actions when able.
#   1.) Pull system info
#   2.) Pull List of available Backups
#   3.) Check Console Name
#   4.) Check OS
#   5.) Check Console Version
#   6.) Check up time
#   7.) Check console memory utilization
#   8.) Check console CPU information
#   9.) Check DB Version
#   10.) Check Java Information
#   11.) List available scan engines
#   12.) List available scan pools
#   13.) List scan pool member engines
#   14.) Update status
#   15.) Console performance monitor and limited issue resolution.
#
# Original idea and the start of much of the code sourced from https://github.com/dc401/NexposeRubyScripts/blob/master/prescan_healthcheck.rb

require 'yaml'
require 'rubygems'
require 'nexpose'
# require 'Time'
require 'io/console'
require 'pp'

include Nexpose

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]
@serviceTimeout = config["servicetimeout"]

# Acceptable uptime value. (uptime at least this value)
nscUpTimeThreshold = 600


#One blink for yes, two blinks for no!
class Beep
    #The use of "self" init a class method rather than instance method
    def self.pass
        print "\a"
    end

    def self.fail
        print "\a \a"
    end
end

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



#
# Connect and authenticate
#
nsc = Nexpose::Connection.new(@host, @userid, @password, @port)

begin
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end

at_exit { nsc.logout }

#Pull system info
sysInfo = nsc.system_information

#Pull List of available Backups
listBackups = nsc.list_backups


# temp read all available info
# pp sysInfo


## Gather console information ##

#Check Console Name
nscName = sysInfo["nsc-name"]

#Check OS
nscOs = sysInfo["os"]

#Check Console Version
nscConsoleVersion = sysInfo["nsc-version"]
nscConsoleUpdateId = sysInfo["last-update-id"]
nscLastUpdate = sysInfo["last-update-date"]
nscVersion = sysInfo["nsc-version"]

#Check up time
nscUpTime = sysInfo["up-time"]

#Check memory utilization
nscFreeMem = sysInfo["ram-free"]
nscTotalMem = sysInfo["ram-total"]

#Check CPU information
nscCpuCount = sysInfo["cpu-count"]
nscCpuSpeed = sysInfo["cpu-speed"]

#Check DB Version
nscDbProduct = sysInfo["db-product"]
nscDbVersion = sysInfo["db-version"]

#Check Java Information
 nscJavaName = sysInfo["java-name"]
 nscJavaHeapMax = sysInfo["java-heap-max"]
 nscJavaHeapCommitted = sysInfo["java-heap-committed"]
 nscJavaHeapFree = sysInfo["java-heap-free"]
 nscJavaHeapUsed = sysInfo["java-heap-used"]
 nscJreVersion = sysInfo["jre-version"]
 nscJavaDaemonThreadCount = sysInfo["java-daemon-thread-count"]
 nscJavaTotalThreadCount = sysInfo["java-total-thread-count"]
 nscJavaThreadPeakCount = sysInfo["java-thread-peak-count"]
 nscJavaStartedThreadCount = sysInfo["java-started-thread-count"]



## Output Collected Data ##
puts #Blank line
puts "---- Console Information ----"
puts #Blank line

#Check Console Name
puts "Console Name: #{nscName}"

#Check OS
puts "Console Operating System: #{nscOs}"

#Check Console Version
puts "Console Version: #{nscConsoleVersion}"
puts "Console Update ID: #{nscConsoleUpdateId}"
puts "Console Last Update: #{nscLastUpdate}"
puts "Console Version: #{nscVersion}"

#Check up time
puts "Console Uptime: #{nscUpTime}"

#Check memory utilization
puts "Console Free Memory: #{nscFreeMem}"
puts "Console Total Memory: #{nscTotalMem}"

#Check CPU information
puts "Number of Console CPUs: #{nscCpuCount}"
puts "Speed of Console Processors: #{nscCpuSpeed}"

#Check DB Version
puts "Console Database Type: #{nscDbProduct}"
puts "Console Database Version: #{nscDbVersion}"

#Check Java Information
puts "Console Java Information"
puts "Name: #{nscJavaName}"
puts "Heap Max: #{nscJavaHeapMax}"
puts "Heap Committed: #{nscJavaHeapCommitted}"
puts "Heap Free: #{nscJavaHeapFree}"
puts "Heap Used: #{nscJavaHeapUsed}"
puts "JRE Version: #{nscJreVersion}"
puts "Daemon Thread Count: #{nscJavaDaemonThreadCount}"
puts "Total Thread Count: #{nscJavaTotalThreadCount}"
puts "Peak Thread Count: #{nscJavaThreadPeakCount}"
puts "Started Thread Count: #{nscJavaStartedThreadCount}"


puts #Blank line
puts "---- List all configured console users ----"
puts #Blank line

nsc.list_users.each do |listUsers|
    puts "User Name: #{listUsers.name}"
    puts "Full Name: #{listUsers.full_name}"
    puts "Email Address: #{listUsers.email}"
    puts "Admin User? #{listUsers.is_admin}"
    puts "Disabled? #{listUsers.is_disabled}"
    puts "Locked? #{listUsers.is_locked}"
    puts "Auth Source: #{listUsers.auth_source}"
    # puts "#{listUsers.}"
    puts # Blank line
end


#Pull the list of available backups
if listBackups.any?
    
    puts #Blank line
    puts "---- List of available Backups on #{@host} ----"
    puts #Blank line
    
    listBackups.each do |backupList|
        puts "Name: #{backupList.name} Description: #{backupList.description} size: #{backupList.size} Date : #{backupList.date}"
    end
    
end


puts #Blank line
puts "---- List of Available Scan Engines ----"
puts #Blank line

# Pull scan engine status / ensure engine status is current.
## versionEngines = nsc.console_command('version engines')

## I don't use a rapid7 hosted scan engine so I've excluded it due to timeouts etc. attempting to refresh it.

# Pull Engine version information to for reference below
engineVer = nsc.engine_versions

engine_ids = Array.new
nsc.engines.each do |engine|
    unless engine.name.include?("Rapid7 Hosted Scan Engine")
        engine_ids << engine.id
    end
end

# Disabled until I track down the new api request location
# Nexpose::AJAX.post(nsc, "/ajax/engine-refreshAll.txml", "engineIds=#{engine_ids * ','}", Nexpose::AJAX::CONTENT_TYPE::FORM)

engine_list = {}
nsc.engines.each do |engine|
    engine_list[engine.id] = "#{engine.name} (#{engine.status})"
    puts "Engine Name: #{engine.name}"
    puts "  Engine ID: #{engine.id}"
    puts "  Scope: #{engine.scope}"
    puts "  Address: #{engine.address}"
    puts "  Port: #{engine.port}"
    puts "  Status: #{engine.status}"
    puts #Blank line

    # puts versionEngines
    engineVer.each do |enVerInfo|
        if enVerInfo["Name"].include?(engine.name)
            puts "  DN: #{enVerInfo["DN"]}"
            puts "  Version: #{enVerInfo["Version"]}"
            puts "  Address (FQDN): #{enVerInfo["Address (FQDN)"]}"
            puts "  Platform: #{enVerInfo["Platform"]}"
            puts "  Serial No: #{enVerInfo["Serial No"]}"
            puts "  Product Name: #{enVerInfo["Product Name"]}"
            puts "  Last Content Update ID: #{enVerInfo["Last Content Update ID"]}"
            puts "  Last Auto Content Update ID: #{enVerInfo["Last Auto Content Update ID"]}"
            puts "  Last Product Update ID: #{enVerInfo["Last Product Update ID"]}"
            puts "  Software Revision: #{enVerInfo["Software Revision"]}"
            puts "  Product ID: #{enVerInfo["Product ID"]}"
            puts "  Version ID: #{enVerInfo["Version ID"]}"
            puts "  VM Version: #{enVerInfo["VM Version"]}"
            puts
        end    
    end
end


engineVer = nsc.engine_versions

puts #Blank line
puts "---- List of Available Engine Pools ----"
puts #Blank line



nsc.engine_pools.each do |enginePool|
        puts "Pool Name: #{enginePool.name}"
        puts "  Pool ID: #{enginePool.id}"
        puts "  Pool Scope: #{enginePool.scope}"
        puts #Blank line
        puts "      Engines <EnginePoolDetailsRequest place holder>"
end



puts #Blank line
puts "---- Diagnostics ----"
puts #Blank line

puts "== Update status =="
puts # blank line

begin
    #Check for the last update
    CTime = Time.now.to_i
    #Check to see if the update was within last 7 days
    if (CTime + 604800) < nscLastUpdate.to_i
        puts "Last Update: OK"
        elsif (CTime + 604800) >= nscLastUpdate.to_i
        puts "Last Update: Not Updated within 7 days"
        puts Time.at(CTime)
        Beep.fail
        puts "Starting update. Please wait."
        nscUpdate = nsc.console_command("updatenow")
        puts nscUpdate
        puts "Pushing update to scan engines. Please wait."
        engineUpdate = nsc.console_command("update engines") # throws error after api changes made to the application
    end
    
    rescue StandardError => err
    print err
    
end

puts # blank line
puts "== Console Performance =="
puts # blank line

begin
    
    #Check to see if up time is greater than 5 minutes
    if nscUpTime.to_i >= nscUpTimeThreshold
        puts "Uptime: #{nscUpTime} - OK "
        elsif nscUpTime.to_i <= nscUpTimeThreshold
        puts "Uptime: #{nscUpTime} - Recent service restart. Potential Issue."
        Beep.fail
    end
    
    rescue StandardError => err
    print err
    
end


begin
    nscMemUse = (nscFreeMem.to_i / nscTotalMem.to_i)
    #Check to see if we are at 75% or greater usage
    if nscMemUse < (0.75)
        puts "Memory Usage: OK #{(nscMemUse)}%"
        elsif nscMemUse >= (0.75)
        puts "Memory Usage: Above 75%"
        puts "Utilization: #{(nscMemUse.to_i * 10)}%"
        Beep.fail
        puts "Attempting to free up Java resources. Please wait."
        GarbageCollect = nsc.console_command("garbagecollect")
        puts GarbageCollect
    end
    
    rescue StandardError => err
    print err
    
end



puts #Blank line
puts "---- End Diagnostics ----"
puts #Blank line

exit
