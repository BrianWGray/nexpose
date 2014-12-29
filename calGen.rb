#!/usr/bin/env ruby
# Brian W. Gray
# 12.23.2014


# This script generates an importable .ics file for scan schedules.
#

# Dependencies required to be installed:
# sudo gem install icalendar
# sudo gem install nexpose
# sudo gem install yaml
# for an example ./conf/nexpose.yaml see https://github.com/BrianWGray/nexpose/blob/master/conf/nexpose.yaml

# misterpaul's scanPlanReporter.rb script was the catalyst for this script.
# https://github.com/misterpaul/NexposeRubyScripts/tree/master/ScanPlanReporter


require 'yaml'
require 'icalendar'
require 'nexpose'
require 'time'
include Nexpose

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]
@icsfilename = config["icsfilename"]
@icsiterations = config["icsitterations"]


# Output filename
output_fn = @icsfilename.to_s

# Number of scan recurrences for the .ics file to include.
numIterations = @icsiterations.to_i

begin
    @nsc = Nexpose::Connection.new(@host, @userid, @password, @port)
    puts 'logging into Nexpose'
    
    begin
        @nsc.login
        rescue ::Nexpose::APIError => err
        $stderr.puts("Connection failed: #{err.reason}")
        exit(1)
    end
    
    puts 'logged into Nexpose'
    at_exit { @nsc.logout }
    
    sites = @nsc.sites
    
    # Create calendar
    cal = Icalendar::Calendar.new
    
    # Check engine status.
    @nsc.console_command('version engines')
    engine_list = {}
    @nsc.engines.each do |engine|
        engine_list[engine.id] = "#{engine.name} (#{engine.status})"
    end
    
    # 'Site Name,Last Scan Start,Last Scan Live Nodes,Scan Template,Scan Engine,Next Scan Start,Schedule'
    
    sites.each do |s|
        
        latest_start_time = status = active = duration = engine_name = 'na'
        
        site = Site.load(@nsc, s.id)
        puts "Pulling Scan data for site: #{site.id}\tname: #{site.name}"
        template = site.scan_template
        
        latest = @nsc.last_scan(site.id)
        if latest
            latest_start_time = latest.start_time
            latest_end_time = latest.end_time # We initially set the end_time to the amount of time the last scan took.
            end_time = latest_end_time
            active = latest.nodes.live
            engine_name = engine_list[site.engine]
            if sched = site.schedules.first
                schedule = "#{sched.type}:#{sched.interval}"
                if sched.max_duration
                    # If we find a max time defined we use it as the end_time to specify the available scan window
                    # this replaces the guess created from the last scan duration.
                    maxDuration = sched.max_duration
                    else
                    maxDuration = 0
                end
            end
            
            if latest.end_time
                duration_sec = latest.end_time - latest_start_time
                hours = (duration_sec / 3600).to_i
                minutes = (duration_sec / 60 - hours * 60).to_i
                seconds = (duration_sec - (minutes * 60 + hours * 3600))
                duration = sprintf('%dh %02dm %02ds', hours, minutes, seconds)
                else
                duration = 'na'
            end
            
            if defined? sched.enabled # Check to see if the site has a schedule enabled.
                
                
                start_time = Time.parse(sched.start)
                end_time = start_time + maxDuration*60
                
                puts "Site:#{site.name} starts #{start_time} Max scan time: #{maxDuration} #{end_time} using #{template} from #{engine_name} on a #{sched.type.upcase} schedule Interval: #{sched.interval}"
                
                event = cal.event
                
                event.summary = "Nexpose Scan for site: #{site.name}"
                event.dtstart = DateTime.parse("#{start_time}")
                event.dtend = DateTime.parse("#{end_time}")
                event.location = "#{engine_name} scanning #{site.name} with template #{template}"
                event.description = "Site:#{site.name} is scheduled to be scanned by #{engine_name} starting at #{start_time} with an expected end time of #{end_time} and a Max scan time of #{maxDuration} minutes. The scan will be completed using scan template: #{template}. Scans for this site have taken ~ #{duration} in the past. This scan is part of a schedule to scan this site with a #{sched.type} schedule type. https://#{@host}:#{@port}/site.jsp?siteid=#{site.id}"
                
                # This is intended to generate Recurrence Rules for the icalendar entries based on
                # http://www.ietf.org/rfc/rfc2445.txt
                # There is still a good bit of work that needs to be done here.
                
                case
                when sched.type == "daily"
                    event.rrule = ["FREQ=DAILY;INTERVAL=#{sched.interval.to_i};COUNT=numIterations*7"] # Iterations are assumed to be in weeks here.
                when sched.type == "weekly"
                    event.rrule = ["FREQ=WEEKLY;INTERVAL=#{sched.interval.to_i};COUNT=numIterations"]
                when sched.type == "monthly-date"
                    event.rrule = ["FREQ=MONTHLY;INTERVAL=#{sched.interval.to_i};COUNT=numIterations"]
                when sched.type == "monthly-day"
                    # I need to take more time to hash out the best way to implement this. Should be fairly straight forward?
                    # event.rrule = ["FREQ=MONTHLY;BYMONTHDAY=#{sched.interval.to_i};COUNT=numIterations"]
                end
                
                cal.add_event(event)
                
                else
                puts "No schedule is enabled for this site"
                
            end
            
            else
            # No scans found.
        end
      end

    output = File.new(output_fn, 'w')
    output.write(cal.to_ical)
    puts "iCalendar file #{output_fn} saved"
    
end

