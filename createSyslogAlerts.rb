#!/usr/bin/env ruby
# Brian W. Gray
# Original creation date 04.28.2015

## Script performs the following
## 1.) Parses all sites and adds a syslog alert
## 2.) Assumes there are no existing alerts - TODO: account for this and update alerts that follow the automated naming convention for this script.
## 3.)

# require gems
require 'yaml'
require 'nexpose'

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)


@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]

# Configure Options for alert template

## Set logserver / port to use in alerts
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
  sites.each do |site|
    begin
      # Load the site configuration to make changes
      site = Nexpose::Site.load(nsc, site.id)
      puts "Evaluating site #{site.name} (id: #{site.id})."

        
        # Initialize a syslog alert for the site.
        syslogAlert = Nexpose::SyslogAlert.new("SysLog_SiteID_#{site.id}", nsc, 1, -1)
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
