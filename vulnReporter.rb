#!/usr/bin/env ruby
# Brian W. Gray 
# Initial code generated: 10.11.2016

# Purpose of this script.
# Query for notifiable vulnerabilities and initiate configured actions.

# This script queries all scans that occured in a specified time range from a console and then takes action
# on systems that have been found to be vulnerable.

# Dependencies required to be installed:
# sudo gem install nexpose
# sudo gem install yaml
# for an example ./conf/nexpose.yaml see https://github.com/BrianWGray/nexpose/blob/master/conf/nexpose.yaml

require 'yaml' # used to parse configuration files
require 'nexpose' # makes the world turn
require 'time' # supports timestamping and time manipulation for queries
require 'active_support/all' # used for time rounding methods
require 'htmlentities' # used for html entity filters
require 'json' # used for json support
require 'csv' # enables csv parsing of reports to hashes
require 'net/smtp' # used to support proof of concept email notices
require 'pp' # lazy trouble shooting

# Default Values from yaml file
configPath = File.expand_path("../conf/pgh-nvs-01.yaml", __FILE__)
config = YAML.load_file(configPath)
vulNotifyPath = File.expand_path("../conf/vulnotify.yaml", __FILE__)
vulNotify = YAML.load_file(vulNotifyPath)

# debug sets verbose output to stdout.
debug = config["vrDebug"]

host = config["hostname"]
userid = config["username"]
password = config["passwordkey"]
port = config["port"]
@nexposeAjaxTimeout = config["nexposeajaxtimeout"]

ageInterval = config["ageInterval"] # => Integer In Hours defines the number of hours to subtract from the specified query time to create a query time window.

# If you need to add auth: https://www.tutorialspoint.com/ruby/ruby_sending_email.htm
mailFrom = config["mailFrom"]
mailServer = config["mailServer"]
mailPort = config["mailPort"]
mailDomain = config["mailDomain"]

# Default Email address for notifications.
defaultEmail = config["defaultEmail"]
mailTo = defaultEmail

# Number of threads alotted for consecutive nexpose_id's queried
threadLimit = config["vulnReporterThreads"]

## Initialize connection timeout values.
## Timeout example provided by JGreen in https://community.rapid7.com/thread/5075
# Here we extend the default web request timeouts for the script
module Nexpose
  class APIRequest
    include XMLUtils
    # Execute an API request
    def self.execute(url, req, api_version='1.2', options = {})
      options = {timeout: @nexposeAjaxTimeout}
      obj = self.new(req.to_s, url, api_version)
      obj.execute(options)
    return obj
    end
  end

  module AJAX
    def self._https(nsc)
      http = Net::HTTP.new(nsc.host, nsc.port)
      http.use_ssl = true
      # http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.read_timeout = @nexposeAjaxTimeout
      http
    end
  end
end

# Support for changing blank csv fields to nil during csv parsing
CSV::Converters[:blank_to_nil] = lambda do |field|
  field && field.empty? ? nil : field
end

# Display generic debug info to stdout
def debug_print(returnedData, debug="false")
  if debug == "true" then
    puts "\r\n[DEBUG]\r\n"
    pp(returnedData) 
  end
end

# Take time in various formats and normalize it to a time object
def normalize_time(time, debug)
  begin
    time = time if(time.is_a?(Time))
    time = Time.parse("#{time.to_s}") if(!time.is_a?(Time))
  rescue
    time = Time.now # Upon failure use the current time value
  end

  return time
end

# Record the current time when the query client is run
def query_time(lastRunFile, time=nil, debug)

  # TODO:
  # write the current run time to the lastRunFile location
  currentRunTime = normalize_time(time, debug)

  lastRunTime = normalize_time(time, debug)

  # Running the query hourly we start the query at the beginning of the hour... (subject to change)
  return lastRunTime.beginning_of_hour()
end

# Determine the last time the reporting client ran a query
def last_query_time(lastRunFile, ageInterval, time=nil, debug)

    # TODO:
    # Was the run successful?
    loggedRunTime = nil
    # Read last run file and pull the last date entry in the file to determine how far back to query for new vulnerabilities
    

    # If there is not previous logged run time assume the default time scope
    loggedRunTime ? lastRunTime = normalize_time(loggedRunTime, debug) : lastRunTime = (normalize_time(time, debug) - ageInterval.hours).to_datetime

    return lastRunTime 
end

# specify initial query times for testing
#queryTime = query_time("./tmp/lastRunFile", "2016-10-12 04:03 -400",debug)
#queryTime = query_time("./tmp/lastRunFile", "2016-09-26 22:51 -400",debug)

queryTime = query_time("./tmp/lastRunFile",nil,debug)
lastQueryTime = last_query_time("./tmp/lastRunFile", ageInterval, queryTime, debug)

# Query a defined nexpose console for all vulnerabilities matching the listed vulnId value
def query_vulns(nexposeId, nsc, debug)

  @sqlSelect = "SELECT * FROM dim_vulnerability "
  @sqlWhere = "WHERE nexpose_id ILIKE '#{nexposeId}';"

  @query = @sqlSelect + @sqlWhere
  debug_print(@query, debug)

  # Query all nexpose_id's matching the provided vulnerabilities within the vulnotify.yaml configuration file.
  @pullVulns = Nexpose::AdhocReportConfig.new(nil, 'sql')
  @pullVulns.add_filter('version', '2.0.2')
  @pullVulns.add_filter('query', @query)
  
  # Generate report to be parsed
  @pulledVulns = @pullVulns.generate(nsc,18000)
  
  # http://stackoverflow.com/questions/14199784/convert-csv-file-into-array-of-hashes
  # http://technicalpickles.com/posts/parsing-csv-with-ruby/
  # Convert the CSV report information provided by the API back into a hashed format. *Should submit an Idea to Rapid7 for JSON report output type from reports?
  @returnedVulns = CSV.parse(@pulledVulns, { :headers => true, :header_converters => :symbol, :converters => [:all, :blank_to_nil] }).map(&:to_hash) if @pulledVulns

  return @returnedVulns
end

# Using the information from "query_vulns()" query all systems that have the Vulnerability ID associated to it within the specified time range of when it was detected.
def vuln_assets(vulnId, queryTime, lastQueryTime, nsc, debug)
  
    # Create a base query containing information about assets associated with the provided Vulnerability ID.
    @sqlSelect = "
WITH

asset_names AS (
                SELECT asset_id, array_to_string(array_agg(host_name), ',') AS names
                FROM dim_asset_host_name
                GROUP BY asset_id
                )

SELECT DISTINCT

asset_id,
ip_address,
port,
dp.name,
mac_address,
host_name,
an.names,
favi.date,
dvs.description,
proofAsText(favi.proof) as proof,
summary,
url,
solution_type,
fix,
estimate

FROM fact_asset_vulnerability_instance favi
JOIN dim_asset da USING (asset_id)
JOIN dim_service dsvc USING (service_id)
JOIN dim_protocol dp USING (protocol_id)
JOIN dim_vulnerability_status dvs USING (status_id)
JOIN dim_vulnerability USING (vulnerability_id)
JOIN dim_vulnerability_solution USING (vulnerability_id)
JOIN dim_solution_highest_supercedence USING (solution_id)
JOIN dim_solution ds ON superceding_solution_id = ds.solution_id
LEFT OUTER JOIN asset_names an USING (asset_id)
LEFT OUTER JOIN dim_scan dsc USING (scan_id)
"
    # Provide the Vulnerability ID and time window for the query
    @sqlWhere = "WHERE (favi.vulnerability_id = '#{vulnId}') AND (favi.date BETWEEN ('#{lastQueryTime}'::timestamp) and ('#{queryTime}'::timestamp))"
    @sqlOrderBy = " ORDER BY host_name, ip_address;"
    @query = @sqlSelect + @sqlWhere + @sqlOrderBy
    debug_print(@query,debug)

    @pullVulns = Nexpose::AdhocReportConfig.new(nil, 'sql')
    @pullVulns.add_filter('version', '2.0.2')
    @pullVulns.add_filter('query', @query)
    
    # Generate report to be parsed
    @pulledVulns = @pullVulns.generate(nsc,18000)
    
    # http://stackoverflow.com/questions/14199784/convert-csv-file-into-array-of-hashes
    # http://technicalpickles.com/posts/parsing-csv-with-ruby/
    # Convert the CSV report information provided by the API back into a hashed format. *Should submit an Idea to Rapid7 for JSON report output type from reports?
    @returnedVulns = CSV.parse(@pulledVulns, { :headers => true, :header_converters => :symbol, :converters => [:all, :blank_to_nil] }).map(&:to_hash) if @pulledVulns

  return @returnedVulns
  
end

# For this proof of concept this is one example action that can be taken for an asset that is found to be vulnerable.
def send_notification(mailFrom, mailTo, mailDomain, mailServer, noticeContent, debug)

# Example Email Notification Template. Modify as needed. Sending HTML email by default because I like it.
message = <<MESSAGE_END
From: #{mailFrom}
To: #{mailTo}
MIME-Version: 1.0
Content-type: text/html
Subject: #{noticeContent[:subject]}

<h1>#{noticeContent[:subject]}</h1>
<p>#{mailTo} is registered as the responsible party for this notice.<br/>
</p>
<p>
A recent scan of #{noticeContent[:ipAddress]} indicates a vulnerability on the system.<br/>
The following issue was detected: #{noticeContent[:vulnTitle]}
</p>
<p>#{noticeContent[:ipAddress]}:#{noticeContent[:port]} / #{noticeContent[:proto]}<br/>
#{noticeContent[:hostName]}<br/>
#{noticeContent[:otherNames]}<br/>
#{noticeContent[:macAddress]}
</p>
<p>
Time of Detection: #{noticeContent[:date]} <br/>
Level of Confidence: #{noticeContent[:confirmation]}<br/>
<h3>Description of the issue:</h3>
#{noticeContent[:description]}

</p>
<h3>Proof:</h3>
#{noticeContent[:proof]}
<p>
<h3>Solution Summary:</h3> 
#{noticeContent[:solSummary]}<br/>
#{noticeContent[:url]}
</p>
#{noticeContent[:solutionType]}<br/>
#{noticeContent[:fix]}
<p>
If you have received this notice in error, please contact it-help@andrew.cmu.edu
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

def report_vulns(vulnIds, queryTime, lastQueryTime, mailFrom, mailTo, mailDomain, mailServer, nsc, debug)
  # Encode HTML entities in output.
  coder = HTMLEntities.new
  
  @vulnAssets = vuln_assets(vulnIds[:vulnerability_id], queryTime, lastQueryTime, nsc, debug)
  if !@vulnAssets.empty? then
    @vulnAssets.each do |assets|
      noticeContent = {} # Ensure noticeContent is cleared
      debug_print(assets[:asset_id],debug)

      # This is not terribly efficient but will improve over time.
      vulnIds[:description] ? @vulnDescription = "#{vulnIds[:description]}" : @vulnDescription = "A description of this vulnerability is not available for this notice."
      assets[:proof] ? @proof = "#{coder.encode(assets[:proof])} " : @proof = "No proof provided"
      assets[:mac_address] ? @macAddress = assets[:mac_address] : @macAddress  = "No machine address available"
      assets[:summary] ? @solSummary = assets[:summary] : @solSummary = "No summary available"
      assets[:url] ? @url = assets[:url] : @url = ""
      assets[:solution_type] ? @solutionType = "Solution Type: #{assets[:solution_type]}" : @solutionType  = ""
      assets[:fix] ? @fix = assets[:fix] : @fix = "Instructions for fixing the issue have not been provided."
      assets[:estimate] ? @estimate = "Estimated remediation time: #{assets[:estimate]}" : @estimate ="No remediation time estemate available."

      noticeContent = {
      contact: mailTo,
      subject: "Vulnerability Notification",
      vulnTitle: "#{vulnIds[:title]}",
      description: @vulnDescription,
      ipAddress: "#{assets[:ip_address]}",
      port: "#{assets[:port]}",
      proto: "#{assets[:name]}",
      macAddress: @macAddress,
      hostName: "#{assets[:hostname]}",
      otherNames: "#{assets[:names]}",
      date: "#{assets[:date]}",
      confirmation: "#{assets[:description]}",
      proof: @proof,
      solSummary: @solSummary,
      url: @url,
      solutionType: @solutionType,
      fix: @fix,
      estimate: @estimate
      # Additional hash values may be added here to provide more information to the notification template.
      }

      # Take Action:
      # Send an email notification to the default contact for PoC
      send_notification(mailFrom, mailTo, mailDomain, mailServer, noticeContent, debug)
    end
  end 
end 

begin
  nsc = Nexpose::Connection.new(host, userid, password, port)
  begin
      nsc.login
  rescue ::Nexpose::APIError => err
      $stderr.puts("Connection failed: #{err.reason}")
      exit(1)
  end
  at_exit { nsc.logout }

  # TODO: Complete threading implementation
  # Initialize query threads 
  actionThreads = []

  vulNotify.each do |vulnToCheck|
    debug_print(vulnToCheck,debug)
    # Collect information for which vulnerability ID's to evaluate
    @returnedVulns = query_vulns(vulnToCheck["vulnId"], nsc, debug).clone 
    if !@returnedVulns.empty? then # Only process vulnerabilities if they exist.
      # Process each returned vulnerability ID
      @returnedVulns.each do |vulnIds|
        debug_print(vulnIds[:nexpose_id],debug)
        # http://stackoverflow.com/questions/1697504/threading-in-ruby-with-a-limit
        # until loop waits around until there are less than the specified number of created threads running before allowing execution of the main thread to continue
        if !vulnIds.empty? then
          until actionThreads.map {|t| t.alive?}.count(true) < threadLimit do sleep 5 end
          actionThreads << Thread.new {
            report_vulns(vulnIds, queryTime, lastQueryTime, mailFrom, mailTo, mailDomain, mailServer, nsc, debug) if vulnToCheck["reporter_types"].include? 'email'
          }
        end
      end
    else
    end 
  end
  # The main thread will block until every created thread returns a value.
  threadOut = actionThreads.map { |t| t.value }
  #actionThreads.each { |t| actionThreads.join }
end


