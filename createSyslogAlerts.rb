#!/usr/bin/env ruby
# Brian W. Gray
# Original creation date 04.28.2015

## Script performs the following
## 1.) Parses all sites and adds a syslog alert
## 2.) Looks for existing alerts in each site with the same name as the new alert and removes them prior to adding the new alert.


# require gems
require 'yaml'
require 'nexpose'
require 'pp'


# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

# Console login configurations
@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]


# Configure Options for alert template

## Alert Name Prefix
alertPrefix = "SysLog_SiteID_"

## Log server / port to use in alerts
logServer = config["logserver"]
logPort = config["logport"]

## Scan alert filters
alertFail   = config["alertFail"]
alertPause  = config["alertPause"]
alertResume = config["alertResume"]
alertStart  = config["alertStart"]
alertStop   = config["alertStop"]

## Vuln alert filters
alertConfirmed      = config["alertConfirmed"]
alertPotential      = config["alertPotential"]
alertSeverity       = config["alertSeverity"]
alertUnconfirmed    = config["alertUnconfirmed"]


nsc = Nexpose::Connection.new(@host, @userid, @password, @port)
begin
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end

puts 'logged into Nexpose'
at_exit { nsc.logout }

# Query the list of sites to work with
sites = nsc.list_sites

# User notification of changes to be made.
puts "Syslog alerts will be added to every site located on this console."

begin
    # Step through each site in the site listing.
    sites.each do |eachSite|
        begin
            # Load the site configuration to make changes
            site = Nexpose::Site.load(nsc, eachSite.id)
            puts "Evaluating site #{site.name} (id: #{site.id})."
            # Check for an existing alert within the site with the configured pre-fix #{alertPrefix}
            if site.alerts.length > 0
                puts "Found #{site.alerts.length} alerts for #{site.name} (id: #{site.id})."
                
                site.alerts.each do |alert|
                    
                    # Remove old syslog alerts with the same alert name.
                    if alert.name.include?("#{alertPrefix}#{site.id}")
                        # Create a new object from the alerts to make changes
                        if alert.alert_type.include?("Syslog")
                            if alert.name.include?("#{alertPrefix}#{site.id}")
                                site.alerts.delete_if{ |obj| obj.name.include?("#{alertPrefix}#{site.id}")}
                                puts "Deleted #{alertPrefix}#{site.id} from alerts for site #{site.name} (id: #{site.id})."
                                
                                # Save the site configuration
                                site.save(nsc)
                                puts "Saved changes to site #{site.name} (id:#{site.id})."
                            end
                        end
                    end
                end
            end
        rescue Exception => err
            puts err.message
        end
        
        begin
        # Initialize a syslog alert for the site.
        syslogAlert = Nexpose::SyslogAlert.new("#{alertPrefix}#{site.id}", nsc, 1, -1)
        puts "Initiated adding #{logServer} to alert for site #{site.name} (id: #{site.id})."
        
        # Set the syslog server to use.
        puts "      Setting #{logServer} as the log receiver"
        syslogAlert.server = logServer # Defined in ./conf/nexpose.yaml
        
        # Set the syslog port to use
        puts "      Setting logging port #{logPort} for the log receiver"
        syslogAlert.server_port = logPort # Defined in ./conf/nexpose.yaml
        
        puts "      Setting the scan filters"
        alertScanFilter = Nexpose::ScanFilter.new # setup scan filter?
        
        ## Scan alert filters
        alertScanFilter.fail = alertFail
        puts "          Fail = #{alertFail}"
        alertScanFilter.pause = alertPause
        puts "          Pause = #{alertPause}"
        alertScanFilter.resume = alertResume
        puts "          Resume = #{alertResume}"
        alertScanFilter.start = alertStart
        puts "          Start = #{alertStart}"
        alertScanFilter.stop = alertStop
        puts "          Stop = #{alertStop}"
        
        # Assign filters to scan_filter
        syslogAlert.scan_filter = alertScanFilter
        
        puts "      Setting the vuln filter"
        alertVulnFilter = Nexpose::VulnFilter.new # setup vuln filter?
        
        ## Vuln alert filters
        alertVulnFilter.confirmed = alertConfirmed
        puts "          Confirmed = #{alertConfirmed}"
        alertVulnFilter.potential = alertPotential
        puts "          Potential = #{alertPotential}"
        alertVulnFilter.severity = alertSeverity
        puts "          Severity = #{alertSeverity}"
        alertVulnFilter.unconfirmed = alertUnconfirmed
        puts "          Unconfirmed = #{alertUnconfirmed}"
        
        # Assign filters to vuln_filter
        syslogAlert.vuln_filter = alertVulnFilter
        
        # Apply alert to site.
        site.alerts << syslogAlert
        
        # Save the site configuration
        puts "      Saving the alert"
        site.save(nsc)
        puts "Changes saved to site #{site.name} (id:#{site.id})."
        
        # Site level error, continue to the next site.
    rescue Exception => err
        puts err.message
    end
end
    
    # Global error, this usually exits the loop and terminates.
rescue Exception => err
    puts err.message
end

puts "Updates completed."
exit
