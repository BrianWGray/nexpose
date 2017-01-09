#!/usr/bin/env ruby

require 'yaml'
require 'nexpose'
include Nexpose

# Default Values from yaml file
config_path = File.expand_path("../conf/nexpose.yaml", __FILE__)
config = YAML.load_file(config_path)

@host = config["hostname"]
@userid = config["username"]
@password = config["passwordkey"]
@port = config["port"]

nsc = Nexpose::Connection.new(@host, @userid, @password, @port)
  
begin
    nsc.login
    rescue ::Nexpose::APIError => err
    $stderr.puts("Connection failed: #{err.reason}")
    exit(1)
    raise
end
at_exit { nsc.logout }
 
# Allow the user to pass in the Scan ID to the script.  
scan_id = ARGV[0].to_i  



# Export the data associated with a single scan, and optionally store it in
# a zip-compressed file under the provided name.
#
# @param [Fixnum] scan_id Scan ID to remove data for.
# @param [String] zip_file Filename to export scan data to.
# @return [Fixnum] On success, returned the number of bytes written to
#   zip_file, if provided. Otherwise, returns raw ZIP binary data.
#
def nsc.scan_log(scan_id, zip_file = nil)
  http = AJAX.https(self)
  headers = { 'Cookie' => "nexposeCCSessionID=#{@session_id}",
              'Accept-Encoding' => 'identity' }
  resp = http.get("/data/scan/log?scan-id=#{scan_id}", headers)

  case resp
  when Net::HTTPSuccess
    if zip_file
      ::File.open(zip_file, 'wb') { |file| file.write(resp.body) }
    else
      resp.body
    end
  when Net::HTTPForbidden
    raise Nexpose::PermissionError.new(resp)
  else
    raise Nexpose::APIError.new(resp, "#{resp.class}: Unrecognized response.")
  end
end


  
nsc.scan_log(scan_id, "scan-#{scan_id}.zip")  
