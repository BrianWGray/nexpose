#!/usr/bin/env ruby

# Date Created: 05.21.2018
# Written by: BrianWGray

# Written for
# https://kb.help.rapid7.com/discuss/5b031d8a01b0ff00038d8b9b

## Script performs the following tasks
## 1.) pull report configuration
## 2.) generate list of report recipients

require 'yaml'
require 'nexpose'
require 'pp'
include Nexpose

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

host = config["hostname"]
userid = config["username"]
password = config["passwordkey"]
port = config["port"]

nsc = Nexpose::Connection.new(host, userid, password, port)

begin
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
end
at_exit { nsc.logout }

# Pull a list of all reports
reportList = nsc.list_reports

# Iterate through each report
reportList.each do |reportDetails|
    # Load report information for each report
    reportInfo = ReportConfig.load(nsc, reportDetails.config_id)

    # If the report has external recipients configured, print the recipient list
    if(reportInfo.delivery.email.respond_to? :recipients) then
        puts("Report: #{reportInfo.name}")
        reportInfo.delivery.email.recipients.each do |eachRecipient|
            puts(eachRecipient)
        end  
    end
end


exit