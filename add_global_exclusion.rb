#!/usr/bin/env ruby

# Date Created: 10.18.2018
# Written by: BrianWGray

# Generated for https://kb.help.rapid7.com/discuss/5bbf13faeb416300039a1efa

## Script performs the following tasks
## 1.) Read addresses from a text file
## 2.) Add addresses to the Global Exclusion list.

# TODO: Possibly change the script to allow loading contents from a csv instead of a text file with an asset entry per line.

## Currently the script loads a text file with a single entry per line.
# Each asset entry may be:
## single ip
## ip range 192.168.0.0/24 | 192.168.0.0-192.168.0.255
## hostname

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
@debug = false

# Any arguments after flags can be grabbed now."
unless ARGV[0]
  $stderr.puts 'Input file is required.'
  exit(1)
end
file = ARGV[0]

def load_file(file)
  # This will fail if the file cannot be read.
  begin
    fileContents = File.read(file).split.uniq
  rescue
      $stderr.puts "Error reading file: #{file}"
      exit(1)
  end

  return fileContents
end

def add_global_exclusion(nsc,assetList)
  globalSettings = GlobalSettings.load(nsc)
  assetList.each do |asset|
    puts "Adding #{asset} to global exclusion list"
    globalSettings.add_exclusion(asset)
  end

  begin
    # Save global exclusion changes
    globalSettings.save(nsc)
    return true # success
  rescue ::Nexpose::APIError => err
    $stderr.puts("Saving Global Settings Failed")
    $stderr.puts("#{err.reason}")
    return false # save failed
  end
end

# Create Nexpose connection and authenticate
nsc = Nexpose::Connection.new(@host, @userid, @password, @port)
begin
  nsc.login
  at_exit { nsc.logout }
rescue ::Nexpose::APIError => err
  $stderr.puts("Connection failed: #{err.reason}")
  exit(1)
end

# Load asset list from file
assetList = load_file(file)
# Load asset list into global exclusions
add_global_exclusion(nsc,assetList)

exit()