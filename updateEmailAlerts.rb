#!/usr/bin/env ruby
# Brian W. Gray
# Original creation date 07.25.2014

## Script performs the following
## 1.) Parses all sites for SMTP alerts
## 2.) Finds SMTP alerts that contain a provided email address
## 3.) Replaces found email address with new email address

# require gems
require 'yaml'
require 'nexpose'
require 'optparse'

# Default Values

config = YAML.load_file("conf/nexpose.yaml") # From file

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]


OptionParser.new do |opts|
  opts.banner = "Usage: #{File::basename($0)} [options] <old email> <new email>"
  opts.separator ''
  opts.separator 'Update an alert email address for each site.'
  opts.separator ''
  opts.separator 'Options:'
  opts.on_tail('--help', 'Print this help message.') { puts opts; exit }
end.parse!

# Input for old and new email addresses.
unless ARGV[0] and ARGV[1]
  $stderr.puts 'The old and new email addresses are required. Use --help for instructions.'
  exit(1)
end

# Assigning the arguments to variables with some assurance that they are proper strings.
oldEmail = ARGV[0].to_s.chomp
newEmail = ARGV[1].to_s.chomp

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

# Query the list of sites to work with
sites = nsc.list_sites

# User notification of changes to be made.
puts "Alerts will be modified to remove #{oldEmail} and add #{newEmail}."

begin
  # Step through each site in the site listing.
  sites.each do |site|
    begin
      # Load the site configuration to make changes
      site = Nexpose::Site.load(nsc, site.id)
      puts "Evaluating site #{site.name} (id: #{site.id})."

      # Check for configured alerts; skip sites without alerts.
      if site.alerts.length > 0
        puts "Found #{site.alerts.length} alerts for #{site.name} (id: #{site.id})."
        site.alerts.each do |alert|

          # Confirm that the alert is type: SMTPAlert.
          # Create a new object from the SMTP alert to make changes
          if alert.type.instance_of? Nexpose::SMTPAlert
            smtpAlert = alert.type

              # Only edit alerts where the old email address is present.
              if smtpAlert.recipients.include?(oldEmail)
                smtpAlert.recipients.delete_if { |r| r == oldEmail }
                puts "Deleted #{oldEmail} from alert for site #{site.name} (id: #{site.id})."

                # Only update the alert with the email address if it isn't already present
                unless smtpAlert.recipients.include?(newEmail)
                  smtpAlert.add_recipient(newEmail)
                  puts "Added #{newEmail} to alert for site #{site.name} (id: #{site.id})."
                end

                # Commit changes from the new alert object to the existing alert.
                # Save the site configuration
                alert.type = smtpAlert
                site.save(nsc)
                puts "Saved changes to site #{site.name} (id:#{site.id})."
              else
                puts "No changes made to #{site.name} (id: #{site.id})."
              end
          end
        end
      end

    # Site level error, continue to the next site.
    rescue Exception => e
      puts e.message
    end
  end

# Global error, this usually exits the loop and terminates.
rescue Exception => e
  puts e.message
end

puts "Updates completed."
exit
