class NexposeIntegration

    require 'nexpose'
    include Nexpose

    def connect (console, nxuser, nxpass)
      @nsc = Connection.new(console, nxuser, nxpass)
      @nsc.login
    end

    def get_all_sites
      all_sites = @nsc.list_sites
    end

    def get_hostnames(site)
      hostnames = []
      site = Site.load(@nsc, site.id)
      assets = site.assets
      assets.each do |asset|
        if asset.is_a?(HostName)
          # Lieberman doesn't like FQDNs
          hostname = asset.host.slice(/^[^.]*/)
          hostnames.push(hostname)
        end
      end
     end

    def save_credential(asset_info)
      site = Site.load(@nsc, asset_info[:site_id])
      newcred = Credential.for_service(asset_info[:service], asset_info[:user], asset_info[:password],asset_info[:realm], asset_info[:hostname], asset_info[:port])
      newcreds = [newcred]
      site.credentials = newcreds
      site.save(@nsc)
    end

    def save_all_credentials_for_site(assets_info, site)
      site = Site.load(@nsc, site)
      newcreds = []
      assets_info.each do |asset_info|
        newcred = Credential.for_service(asset_info[:service], asset_info[:user], asset_info[:password],asset_info[:realm], asset_info[:hostname], asset_info[:port])
        newcreds.push(newcred)
      end
      site.credentials = newcreds
      site.save(@nsc)
    end

    def start_scan_site(site)
      site = Site.load(@nsc, site)
      site.scan(@nsc)
    end
end