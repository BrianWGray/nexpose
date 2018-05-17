#!/usr/bin/env ruby

# Date Created: 05.16.2018
# Written by: BrianWGray

# Written for
# https://kb.help.rapid7.com/v1.0/discuss/5afd940ccbdae50003fe0e2e

## Script performs the following tasks
## 1.) Demonstrate creating a DAG using criterion
## 2.) Create new asset group
## 3.) Add addresses to the created asset group based on a regex search.

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

assetarray = []
assetarray << Criterion.new(Search::Field::IP_ADDRESS,Search::Operator::LIKE,"^10\\\.\\\d{1,3}\\.\\\d{1,3}\\\.11$")


crag = Criteria.new(assetarray,"OR")
dag = DynamicAssetGroup.new('test_dag',crag,'test description')

dag.save(nsc)

pp(dag)

exit