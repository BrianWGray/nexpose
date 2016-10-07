#!/usr/bin/env ruby
# Brian W. Gray
# Initial Creation Date: 9.30.2016


# Purpose of this script.
# Written as a POC for:
# https://community.rapid7.com/thread/8990

# This script queries all scheduled scans on a console and the contact email out of each site 
# then sends an email notification about when the scan will occur with a 24 hour advanced notice..
#

# Dependencies required to be installed:
# sudo gem install nexpose
# sudo gem install yaml
# for an example ./conf/nexpose.yaml see https://github.com/BrianWGray/nexpose/blob/master/conf/nexpose.yaml


require 'yaml'
require 'nexpose'
require 'time'
require 'pp'
require 'net/smtp'
include Nexpose

# Default Values from yaml file
config_path = File.expand_path("../conf/pgh-nvs-01.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]

# If you need to add auth: https://www.tutorialspoint.com/ruby/ruby_sending_email.htm
mailFrom = config["mailFrom"]
mailServer = config["mailServer"]
mailPort = config["mailPort"]
mailDomain = config["mailDomain"]

# If an organizations contact email is not configured for a site send the notice to the defaultEmail address.
defaultEmail = config["defaultEmail"]
mailTo = defaultEmail


# The intent for the mailer times is as follows:
# a mailerRange of 24 hours checks for scheduled scans 24 hours from the time of the script running.
# If the script is run at 11am then the script is looking for scans the next day at 11am. 
# The scans won't always be exactly 24 hours from now so we provide a mailerWindow of 60 minutes 
# This means that any scheduled scan the next day between 11am and 12 will be in the notify window.

# Values are in seconds and ultimately handled via epoch values
mailerRange = ((60 * 60) * 24)
mailerWindow = ((60 * 60)) # * 24)# => window of time for scheduled scans to be alerted for


# Replace Time.parse(time.to_s).to_s assignments with a time normalizing method - BWG
def normalize_time(time)
    begin  
        time = time if(time.is_a?(Time))
        time = Time.parse("#{time.to_s}") if(!time.is_a?(Time))
    rescue 
        time = Time.now # Upon failure use the current time value
    end

    return time
end


def send_notification(mailFrom, mailTo, mailDomain, mailServer, noticeContent)

# These values don't really need to be re-assigned to local variables but I did it.
@summary = noticeContent[:summary]
@location = noticeContent[:location]
@dtstart = noticeContent[:dtstart]
@template = noticeContent[:template]
@description = noticeContent[:description]


# Example Email Notification Template. Modify as needed. Sending HTML email by default because I like it.
message = <<MESSAGE_END
From: #{mailFrom}
To: #{mailTo}
MIME-Version: 1.0
Content-type: text/html
Subject: #{@summary}

<h1>Vulnerability Scan Notice</h1>
<br/>
<p><b>The listed email address #{mailTo} is registered as the primary notification list for this notice.</b></p?
<br/>
<p>
<b>#{@summary}</b>
<br/>
A vulnerability scan is scheduled to run against #{@location} starting #{@dtstart}<br/>
The scheduled scan is assigned the following template: #{@template}
</p>
<p>
#{@description}
</p><p><br/>
If you believe you have received this notice in error please contact help@example.com.
</p>


MESSAGE_END

    begin
        Net::SMTP.start(mailServer) do |smtp|
            smtp.send_message message, mailFrom, mailTo
        end

    rescue => err
        $stderr.puts("Fail: #{err}")
        exit(1)
    end

end

begin
    nsc = Nexpose::Connection.new(@host, @userid, @password, @port)
    
    begin
        nsc.login
        rescue ::Nexpose::APIError => err
        $stderr.puts("Connection failed: #{err.reason}")
        exit(1)
    end
    at_exit { nsc.logout }

    sites = nsc.sites

    begin    
        sites.each do |s|
           
            latest_start_time = status = active = 'na'
           
            site = Site.load(nsc, s.id)
            # puts "Pulling Scan data for site: #{site.id}\tname: #{site.name}"
           
            site.schedules.each do |sched|
                begin

                    schedule = "#{sched.type}:#{sched.interval}"

                    if defined? sched.enabled # Check to see if the site has a schedule enabled.

                        start_time = normalize_time(sched.next_run_time) # => Time of the Next scheduled scan
                        currentTime = Time.now.to_i # =>  Current Time to calculate a time range for which notifications to send.
                        rangeTime = currentTime + mailerRange
                        timeRange = (rangeTime)..(rangeTime + mailerWindow) # => Range of time from the script run time to notify for.

                        if timeRange === start_time.to_i

                            # puts "Site:#{site.name} starts #{start_time} on a #{sched.type.upcase} schedule Interval: #{sched.interval}"
                            if !site.organization.email.nil?
                                orgMail = "#{site.organization.email}" 
                            else
                                orgMail = "#{defaultEmail}"
                            end
    
                            noticeContent = {
                                contact: orgMail,
                                summary: "Vulnerability Scan for site: #{site.name}",
                                dtstart: "#{start_time}",
                                location: "#{site.name}",
                                template: "#{sched.scan_template_id}",
                                description: "Site: #{site.name} is scheduled to be scanned starting at #{start_time}. This scan is part of a schedule to scan this site with a #{sched.type} schedule type. https://#{@host}:#{@port}/site.jsp?siteid=#{site.id}"
                                # Additional hash values may be added here to provide more information to the notification template.
                            }
                       
                            # Call the mail function to email this schedule.
                            send_notification(mailFrom, mailTo, mailDomain, mailServer, noticeContent)
                        end   
                    end
                rescue => err
                    $stderr.puts("Fail: #{err}")
                    exit(1)
                end 
            end          
        end

    end
end
