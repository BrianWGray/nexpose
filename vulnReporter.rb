#!/usr/bin/env ruby
# Brian W. Gray 10.11.2016



# Purpose of this script.
# Query for notifiable vulnerabilities and initiate configured actions.

# This script queries all scans that occured in a specified time range from a console and then takes action
# on systems that have been found to be vulnerable.


# Dependencies required to be installed:
# sudo gem install nexpose
# sudo gem install yaml
# for an example ./conf/nexpose.yaml see https://github.com/BrianWGray/nexpose/blob/master/conf/nexpose.yaml

require 'yaml'
require 'nexpose'
require 'time'
require 'active_support/all'
require 'htmlentities'
require 'json'
require 'csv'
require 'net/smtp'
require 'pp'
# require_relative './static_networks'
#require_relative './nls_client'


# Default Values from yaml file
configPath = File.expand_path("../conf/pgh-nvs-01.yaml", __FILE__)
config = YAML.load_file(configPath)
vulNotifyPath = File.expand_path("../conf/vulnotify.yaml", __FILE__)
vulNotify = YAML.load_file(vulNotifyPath)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]

# If you need to add auth: https://www.tutorialspoint.com/ruby/ruby_sending_email.htm
mailFrom = config["mailFrom"]
mailServer = config["mailServer"]
mailPort = config["mailPort"]
mailDomain = config["mailDomain"]

# Default Email address for notifications.
defaultEmail = config["defaultEmail"]
mailTo = defaultEmail

thread_limit = 25

#vulnId = "cmty-ssh-default-account-%"
#nexposeId = "cmty-ssh-default-account-root-password-raspberrypi"

CSV::Converters[:blank_to_nil] = lambda do |field|
  field && field.empty? ? nil : field
end

# Take time in various formats and normalize it to a time object
def normalize_time(time)
  begin
    time = time if(time.is_a?(Time))
    time = Time.parse("#{time.to_s}") if(!time.is_a?(Time))
  rescue
    time = Time.now # Upon failure use the current time value
  end

  return time
end

# Record the current time when the query client is run
def query_time(lastRunFile,time=nil)

  # write the current run time to the lastRunFile location
  currentRunTime = normalize_time(time)

  lastRunTime = normalize_time(time)

  # Running the query hourly we start the query at the beginning of the hour... (subject to change)
  return lastRunTime.beginning_of_hour()
end

# Determine the last time the reporting client ran a query
def last_query_time(lastRunFile,ageInterval,time=nil)

    # Was the run successful?
    loggedRunTime = nil
    # Read last run file and pull the last date entry in the file to determine how far back to query for new vulnerabilities
    

    # If there is not previous logged run time assume the default time scope
    loggedRunTime ? lastRunTime = normalize_time(loggedRunTime) : lastRunTime = (normalize_time(time) - ageInterval.hours).to_datetime

    return lastRunTime 
end

#####
#
# Set Query Time Values
#
#####


ageInterval = 24 # => Integer In Hours defines the number of hours to subtract from the query time to create a query time window.

#queryTime = query_time("./tmp/lastRunFile", "2016-10-12 04:03 -400")
#queryTime = query_time("./tmp/lastRunFile", "2016-09-26 22:51 -400")

queryTime = query_time("./tmp/lastRunFile")
lastQueryTime = last_query_time("./tmp/lastRunFile", ageInterval, queryTime)


# Query a defined nexpose console for all vulnerabilities matching the listed vulnId value
def query_vulns(nexposeId, nsc)
  # @scandate = time # normalize_time(time)

  @sqlSelect = "SELECT * FROM dim_vulnerability "
  @sqlWhere = "WHERE nexpose_id ILIKE '#{nexposeId}';"

  @query = @sqlSelect + @sqlWhere

  # Run a query to pull all available tags beginning with #{tagPrefix}.
  @pullVulns = Nexpose::AdhocReportConfig.new(nil, 'sql')
  @pullVulns.add_filter('version', '2.0.2')
  @pullVulns.add_filter('query', @query)
  
  # http://stackoverflow.com/questions/14199784/convert-csv-file-into-array-of-hashes
  # http://technicalpickles.com/posts/parsing-csv-with-ruby/
  @returnedVulns = CSV.parse(@pullVulns.generate(nsc,18000).chomp, { :headers => true, :header_converters => :symbol, :converters => [:all, :blank_to_nil] }).map(&:to_hash)

  return @returnedVulns
end

# Using the information from "query_vulns()" or a specific tag name query all systems that have the tag associated to it
def vuln_assets(vulnId, queryTime, lastQueryTime, nsc)
  
    # Create Query containing assets with a specific associated tag.
    @sqlSelect = "
WITH

asset_names AS (
                SELECT asset_id, array_to_string(array_agg(host_name), ',') AS names
                FROM dim_asset_host_name
                GROUP BY asset_id
                )

SELECT 

asset_id,
ip_address,
port,
dp.name,
mac_address,
host_name,
an.names,
favi.date,
dvs.description,
proofAsText(favi.proof) as proof

FROM fact_asset_vulnerability_instance favi
JOIN dim_asset da USING (asset_id)
JOIN dim_service dsvc USING (service_id)
JOIN dim_protocol dp USING (protocol_id)
JOIN dim_vulnerability_status dvs USING (status_id)
LEFT OUTER JOIN asset_names an USING (asset_id)
LEFT OUTER JOIN dim_scan dsc USING (scan_id)
"
  
    @sqlWhere = "WHERE (favi.vulnerability_id = '#{vulnId}') AND (favi.date BETWEEN ('#{lastQueryTime}'::timestamp) and ('#{queryTime}'::timestamp))"
    @sqlOrderBy = " ORDER BY host_name, ip_address;"
    @query = @sqlSelect + @sqlWhere + @sqlOrderBy

    @pullVulns = Nexpose::AdhocReportConfig.new(nil, 'sql')
    @pullVulns.add_filter('version', '2.0.2')
    @pullVulns.add_filter('query', @query)

    @returnedVulns = CSV.parse(@pullVulns.generate(nsc,18000).chomp, { :headers => true, :header_converters => :symbol, :converters => [:all, :blank_to_nil] }).map(&:to_hash)

    return @returnedVulns
  
end

def query_solution(nexposeId, vulnId, assetId, nsc)
  # @scandate = time # normalize_time(time)

  @sqlSelect = "SELECT
  summary,
  url,
  solution_type,
  fix,
  estimate

  FROM dim_asset_vulnerability_solution
  JOIN dim_solution_highest_supercedence dshs USING (solution_id)
  JOIN dim_solution ds ON ds.solution_id = dshs.superceding_solution_id 
  "

  @sqlWhere = "WHERE asset_id = #{assetId.to_i} AND vulnerability_id = #{vulnId.to_i} AND nexpose_id ILIKE '#{nexposeId}';"
  @query = @sqlSelect + @sqlWhere


  # Run a query to pull all available tags beginning with #{tagPrefix}.
  @pullSolution = Nexpose::AdhocReportConfig.new(nil, 'sql')
  @pullSolution.add_filter('version', '2.0.2')
  @pullSolution.add_filter('query', @query)
  
  # http://stackoverflow.com/questions/14199784/convert-csv-file-into-array-of-hashes
  # http://technicalpickles.com/posts/parsing-csv-with-ruby/
  @returnedSolution = CSV.parse(@pullSolution.generate(nsc,18000).chomp, { :headers => true, :header_converters => :symbol, :converters => [:all, :blank_to_nil] }).map(&:to_hash)

  return @returnedSolution

end


# Display hash output to stdout
def test_notify_stdout(returnedData)
  # pp(returnedData)
end


def send_notification(mailFrom, mailTo, mailDomain, mailServer, noticeContent)

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
Level of Confidence: #{noticeContent[:confirmation]}
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


def report_vulns(nexposeId, queryTime, lastQueryTime, mailFrom, mailTo, mailDomain, mailServer, nsc)
  # Collect information 

  returnedVulns = query_vulns(nexposeId, nsc).clone
  test_notify_stdout(returnedVulns) # Display a list of available tags on screen for dev
  
  #@static_nets = StaticNetworks.new(config["static_networks"])
  #
  #nls_config = nil
  #config["preprocessors"].each {|preproc_config|
  #        if(preproc_config["type"] == "nls")
  #          nls_config = preproc_config
  #        end
  #}
  #@nls_client = NLSLookup.new(nls_config)


  # Process each returned vulnerability ID
  returnedVulns.each do |vulnIds|
    vulnAssets = vuln_assets(vulnIds[:vulnerability_id], queryTime, lastQueryTime, nsc)
    vulnAssets.each do |assets|
      test_notify_stdout(assets)
      querySolution = query_solution(vulnIds[:nexpose_id], vulnIds[:vulnerability_id], assets[:asset_id], nsc).first
      test_notify_stdout(querySolution)

      # @nls_response = @nls_client.lookup(assets[:ip_address],assets[:date])

      # Encode HTML entities in output.
      coder = HTMLEntities.new


      assets[:proof] ? @proof = "#{coder.encode(assets[:proof])} %>" : @proof = ""
      assets[:mac_address] ? @macAddress = assets[:mac_address] : @macAddress  = ""
      querySolution[:summary] ? @solSummary = querySolution[:summary] : @solSummary = ""
      querySolution[:url] ? @url = querySolution[:url] : @url = ""
      querySolution[:solution_type] ? @solutionType = "Solution Type: #{querySolution[:solution_type]}" : @url = ""
      querySolution[:fix] ? @fix = querySolution[:fix] : @fix = ""
      querySolution[:estimate] ? @estimate = "Estimated remediation time: #{querySolution[:estimate]}" : @estimate =""

      noticeContent = {
      contact: mailTo,
      subject: "Vulnerability Notification",
      vulnTitle: "#{vulnIds[:title]}",
      description: "#{vulnIds[:description]}",
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
      #nlsResponse: @nls_response

      # Additional hash values may be added here to provide more information to the notification template.
      }
      # Send an email notification to the default contact
      send_notification(mailFrom, mailTo, mailDomain, mailServer, noticeContent)
    end
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
  
  #Initialize query threads
  actionThreads = []
  

  # Parse through the list of Nexpose Vulnerability ID's from the vulnerability notify configuration file and process the vulnerability.
  vulNotify.each do |vulnToCheck|
    # TODO Modify to account for case senstiivity etc.
    # http://stackoverflow.com/questions/1697504/threading-in-ruby-with-a-limit
    # until loop waits around until there are less than the specified number of created threads running before allowing execution of the main thread to continue
    until actionThreads.map {|t| t.alive?}.count(true) < thread_limit do sleep 5 end
    actionThreads << Thread.new {
      report_vulns(vulnToCheck["vulnId"], queryTime, lastQueryTime, mailFrom, mailTo, mailDomain, mailServer, nsc) if vulnToCheck["reporter_types"].include? 'email'
    }
  end

  # The main thread will block until every created thread returns a value.
  threadOut = actionThreads.map { |t| t.value }
  #actionThreads.each { |t| thr.join }

end





