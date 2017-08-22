#!/usr/bin/env ruby
# Brian W. Gray
# https://github.com/BrianWGray
# Original creation date 08.22.2017

## Script performs the following
## 1.) Parses all sites and adds an smtp alert
## 2.) Looks for existing alerts in each site with the same name as the new alert and removes them prior to adding the new alert.

# require gems
require 'yaml'
require 'nexpose'
require 'pp'

# Default Values from yaml file
# The values may be configured manually, this is for the script creators benefit. 
# An example configuration file is available in the source git repository
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

# Console login configurations
@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]

# Configure Options for alert template

## Alert Name Prefix
alertPrefix = "SMTPAlert_SiteID_"

## SMTP server / port to use in alerts
smtpServer = "localhost" #config["smtpserver"]
smtpPort = 25 #config["smtpport"] # Not currently used

# Mail Info
sender = "vulnsender@example.com"  #config["smtpsender"]
recipients = ["recipients@example.com"] #config["smtprecipients"] # must be in array form.

## Scan alert filters
alertFail   = 1 #config["alertFail"]
alertPause  = 1 #config["alertPause"]
alertResume = 1 #config["alertResume"]
alertStart  = 1 #config["alertStart"]
alertStop   = 1 #config["alertStop"]

## Vuln alert filters
alertConfirmed      = 1 #config["alertConfirmed"]
alertPotential      = 1 #config["alertPotential"]
alertSeverity       = 1 #config["alertSeverity"]
alertUnconfirmed    = 1 #config["alertUnconfirmed"]

nsc = Nexpose::Connection.new(@host, @userid, @password, @port)
begin
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end
at_exit { nsc.logout }

# Query the list of sites to work with
sites = nsc.list_sites

# User notification of changes to be made.
puts "SMTP alerts will be added to every site located on this console."

begin
    # Step through each site in the site listing.
    sites.each do |eachSite|
        begin
            # Load the site configuration to make changes
            site = Nexpose::Site.load(nsc, eachSite.id)
            puts "\nEvaluating site #{site.name} (id: #{site.id})."
            # Check for an existing alert within the site with the configured pre-fix #{alertPrefix}
            if site.alerts.length > 0
                puts "Found #{site.alerts.length} alerts for #{site.name} (id: #{site.id})."
                
                site.alerts.each do |alert|
                    # Remove old alerts with the same alert name.
                    if alert.alert_type.include?("SMTP")
                        # Create a new object from the alerts to make changes
                        if alert.alert_type.include?("SMTP")
                            if alert.name.include?("#{alertPrefix}#{site.id}")
                                site.alerts.delete_if{ |obj| obj.alert_type.include?("SMTP")}
                                puts "Deleted #{alert.name} from alerts for site #{site.name} (id: #{site.id})."
                                
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
        # Initialize an alert for the site.
        smtpAlert = Nexpose::SMTPAlert.new("#{alertPrefix}#{site.id}", sender, smtpServer, recipients, 1, -1, 1)

        puts "Initiated adding #{alertPrefix}#{site.id} alert for site #{site.name} (id: #{site.id})."
        puts "      Set alert mail recipients #{recipients} for alerts"
        puts "      Set sender address #{sender} for alerts"
        puts "      Set SMTP server #{smtpServer} for alerts"
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
        smtpAlert.scan_filter = alertScanFilter
        
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
        smtpAlert.vuln_filter = alertVulnFilter
        
        # Save the alert configuration
        puts "      Saving the alert"
        smtpAlert.save(nsc, site.id)

        puts "Alert changes saved to site #{site.name} (id:#{site.id})."
        
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


