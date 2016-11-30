# Nexpose <-> Lieberman integration script.
# The following gems need to be installed: nexpose
# This script will perform the following steps:
# 1.- Query nexpose for a list of sites.
# 2.- Go site by site and retrieve the assets.
# 3.- For all assets that are hostnames (not ips) it'll query lieberman for passwords.
# 4.- For those that could checkout passwords it'll save back those credentials back into nexpose.
# 5.- Kick a scan of the site if the setting for it below was set to yes.
# For support, please email integrations_support@rapid7.com with the issue and a copy of the log.


# SCRIPT CONFIGURATION:
# Nexpose console information.
# Nexpose IP / Hostname.
@console = '192.168.99.190'

# Nexpose username.
@nxuser = 'nxadmin'

# Nexpose Password.
@nxpass = 'nxadmin'

# Start scan after site is updated?
@scan = 'N'

# LOGGING.
# This script includes a logger, all output will be sent to the file service_now.log in the directory
# where this script is run.
require 'Logger'
$LOG = Logger.new('lieberman.log', 'monthly')

# Valid log levels: Logger::DEBUG Logger::INFO Logger::WARN Logger::ERROR Logger:FATAL
$LOG.level = Logger::INFO

class LiebermanIntegration
  require "net/http"
  require "uri"
  require_relative "nexpose_integration"

  # Lieberman Web SDK URL.
  @@lieberman_instance = "https://lscerpm-2012/PWCWEB/ClientAgentRequests.asp"
  # Lieberman Authenticator domain.
  @@lieberman_authenticator = "demo"
  # Lieberman username.
  @@lieberman_user = "rapid7"
  # Lieberman password
  @@lieberman_password = "R@,o!D7p@ssw0rd"

  def lieberman_login
    $LOG.info "Login to Lieberman."
    uri = URI.parse("#{@@lieberman_instance}?Command=Login&Authenticator=#{@@lieberman_authenticator}&LoginUsername=#{@@lieberman_user}&LoginPassword=#{@@lieberman_password}")
    http = Net::HTTP.new(uri.host, uri.port)
    #http.set_debug_output $stdout
    request = Net::HTTP::Get.new(uri.request_uri)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    response = http.request(request)
    token = response.body
    raise "Could not connect." if token.nil?
    raise "Could not authenticate. Check your credentials."  unless token.start_with?('Success')
    token_array = token.split(';')
    @login_token = token_array[1]
    $LOG.info "Obtained Lieberman credentials."
  end

  def get_account_info(hostname)
    begin
      $LOG.info "Searching for account information for #{hostname}."
      uri = URI.parse("#{@@lieberman_instance}?Command=ListStoredAccountsForSystem&AuthenticationToken=#{@login_token}&SystemName=#{hostname}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      #http.set_debug_output $stdout
      request = Net::HTTP::Get.new(uri.request_uri)

      response = http.request(request)
      token = response.body
      begin
        if token.start_with?('Success')
          token_array = token.split(';')
          account_info = token_array[1]
          if account_info.include? "Linux" then service = "ssh"
          else service = "cifs"
          end
          namespace =  account_info.slice(/^[^\\]*\\/).gsub(/\\$/, '').gsub(/\(.*\)/, '')
          account_login = account_info.slice(/\\([^\$]*)\$/).gsub(/\\/, '').gsub(/\$/, '')
          $LOG.info "Found account information for #{hostname}."
          account = {:hostname => hostname, :realm => namespace, :user => account_login, :service => service}
        else
          $LOG.info "Could not find account information for #{hostname} in Lieberman."
          account
        end
      rescue Exception
        $LOG.info "Could not find account information about #{hostname} continuing with the next account."
        account
      end
    rescue
      $LOG.info "Lieberman Login token not set."
    end
  end

  def get_password_for_system(account)
    raise "Account information cannot be null or empty." if account.nil? or account.empty?
      begin
      realm = account[:realm]
      user = account[:user]
      hostname = account[:hostname]
      service = account[:service]

      uri = URI.parse("#{@@lieberman_instance}?Command=GetPasswordFromStore&AuthenticationToken=#{@login_token}&SystemName=#{hostname}&Namespace=#{realm}&AccountName=#{user}&Comment=Nexpose")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      #http.set_debug_output $stdout
      request = Net::HTTP::Get.new(uri.request_uri)

      response = http.request(request)
      token = response.body

      if token.start_with?('Success')
        $LOG.info "Found password for #{hostname}"
        token_array = token.split(';')
        pre_password = token_array[1].split('=')
        full_account = {:service => service, :realm => realm, :user => user, :hostname => hostname, :password => pre_password[1]}
      else
        $LOG.info "Could not retrieve password for #{hostname} in Lieberman. Check your permissions."
        full_account
      end
      rescue Exception
        $LOG.info "Could not retrieve password for #{hostname}."
        full_account
      end
  end

end


# Connects and login to Lieberman
lieberman = LiebermanIntegration.new
lieberman.lieberman_login

# Connects to Nexpose.
nexpose = NexposeIntegration.new()
nexpose.connect(@console, @nxuser, @nxpass)

# Get all the sites in Nexpose.
all_sites = nexpose.get_all_sites
raise "No sites found." if all_sites.empty? or all_sites.nil?

# Resaves every site with the new credentials.
all_sites.each do |site|

  # Get all the hostnames for the site.
  hostnames = nexpose.get_hostnames(site)
  next if hostnames.empty?

  all_creds = []

  # Queries Lieberman for all the credentials for all the hostnames.
  hostnames.each do |hostname|
    account_info = lieberman.get_account_info(hostname.host.slice(/^[^.]*/))
    next if account_info.nil? or account_info.empty?
    fullcred = lieberman.get_password_for_system(account_info)
    next if fullcred.nil? or fullcred.empty?
    all_creds.push(fullcred)
  end

  # Saves the site with the credentials.
  $LOG.info "Saving credentials for site-id:  #{site.id}"
  nexpose.save_all_credentials_for_site(all_creds, site.id)
  if @scan == 'Y'
    $LOG.info "Starting scan for #{site.id}"
    nexpose.start_scan_site site.id
  end
end