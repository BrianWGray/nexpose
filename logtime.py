#-------------------------------------------------------------------------------
# Name:        logtime
# Purpose:     Find asset scan times in Nexpose scan logs
#
# Author:      Gavin Schneider
#
# Created:     2013-01-29
# Updated:     2013-09-03
# Copyright:   (c) Gavin 2013
# Licence:     WTFPL
#-------------------------------------------------------------------------------


from datetime import datetime, timedelta
from optparse import OptionParser
from itertools import izip
import re
import csv

#Nexpose log timestamp format, used for converting times
time_format = '%Y-%m-%dT%H:%M:%S'
default_timestamp = timedelta(0)

#csv headers
headers = ['Site', 'Asset', 'Open TCP Ports', 'Open UDP Ports', 'Discovery Duration', 'URLs Spidered', 'Spider Duration', 'Node Duration', 'Total Duration', 'Completed', 'TCP Port List', 'UDP Port List', 'Vulnerabilities', 'Fingerprint Certainty']
summary_headers = ['Site', 'Assets Logged', 'Live Assets', 'Assets Scanned', 'Total Scan Duration', 'High Duration Asset', 'High Duration', 'Low Duration Asset', 'Low Duration']

#match site name
sitePattern = re.compile('\[Site: (?P<site>.*?)\]')
#match scan start / pause / stop (TODO: use this to split a nse.log)
scanStartPattern = re.compile('Scan for site')
scanPausePattern = re.compile('Scan paused')
scanStopPattern = re.compile('\[Site: .*?\] (Scan stopped|Scan completed)')
#should match any ipv4 address (now constrained to be within brackets)
ipPattern = re.compile('[:\[](?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\]]')
ipPattern2 = re.compile('[:\[|\[Target: ](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\]]')
#matches Nexpose log timestamp format
timePattern = re.compile('^(19[0-9]{2}|2[0-9]{3})-(0[1-9]|1[012])-([123]0|[012][1-9]|31)T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])')
#matches keywords in Nexpose logs
startPattern = re.compile('starting node scan')
endPattern = re.compile('Freeing node cache data')
#updated nmap log message regexes
alivePattern = re.compile('\[(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] ALIVE \(reason=(.*?):')
deadPattern = re.compile('\[(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] DEAD \(reason=(.*?)\)')
tcpPattern = re.compile('\[(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<port>\d{0,5})/TCP\] OPEN \(reason=(?P<reason>.*?):')
udpPattern = re.compile('\[(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<port>\d{0,5})/UDP\] OPEN \(reason=(?P<reason>.*?):')
udp2Pattern = re.compile('maybe open UDP ports')
spiderStartPattern = re.compile('\[Thread: SPIDER::do-http-spiderv2-setup@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\] \[Site: (?P<site>.*?)\] \[(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<port>\d{1,5})\]')
spiderEndPattern = re.compile('\[Thread: .*?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\] \[Site: (?P<site>.*?)\] \[(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] Closing service: Ne[Xx]poseWebSpider\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(?P<port>\d{1,5})\]  \(source: (?P<source>.*?)\)')
spiderSummaryPattern = re.compile('\[Thread: .*?:(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] \[Site: (?P<site>.*?)\] Shutting down spider \((?P<urls>.*?) URLs spidered in')
sysFingerprintPattern = re.compile('\[(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] (?P<action>.*?) SystemFingerprint.*?\[certainty=(?P<certainty>.*?)\]\[description=(?P<description>.*?)\].*? source: (?P<source>.*?)$')
vulnerablePattern = re.compile('- VULNERABLE')

def main():
    
    def verbose_output(site, message, timestamp):
        """Print or write to file a verbose message when verbose output is enabled."""
        verbosetext = '[Site: {0}] {1} at {2}'.format(site, message, timestamp)
        if options.verbose:
            print verbosetext
        if options.outverbose:
            outf.write(verbosetext + '\n')

    def init_asset(site, timestamp):
        """Create dictionary for a newly added asset"""
        asset_dict = {'sitename':site,'alive': '','tcptime':'','tcpports':0,'tcpportlist':[],'udptime':'','udpports':0,'udpportlist':[],'udpmaybeports':'','udpmaybeportlist':'','nodestart':'','nodeend':'','spiderstart':'','spiderend':'','urls':0, 'last_timestamp':timestamp, 'first_timestamp':timestamp, 'completed': 'No', 'vulns':0, 'fingerprint_certainty':''}
        return asset_dict

    def init_site(timestamp):
        """Create dictionary for a newly added site"""
        site_dict = {'scan_start':[], 'scan_pause':[], 'scan_stop':[], 'scan_durations':[], 'scan_total_duration':'', 'last_timestamp':timestamp, 'first_timestamp':timestamp, 'dead_ips':[], 'completed': 'No'}
        return site_dict

    def calc_duration(start, end):
        """Calculate the duration between two timestamps"""
        duration = datetime.strptime(end, time_format) - datetime.strptime(start, time_format)
        return duration

    usage = "usage: %prog <file> [options]"
    parser = OptionParser(usage)
    parser.add_option("-o", "--out", dest="outfile", help="Output results to flat text FILE (optional).", metavar="FILE")
    #todo: implement csv output
    parser.add_option("-c", "--csv", dest="csvfile", help="Output results to CSV FILE (optional)", metavar="FILE")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Enable verbose console output. Warning: very spammy!")
    parser.add_option("-u", "--outverbose", dest="outverbose", default=False, help="Enable verbose file output. Warning: very spammy!", metavar="FILE")
    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Only show brief summary in console output.")

    (options, args) = parser.parse_args()

    if len(args) < 1:
        parser.error("A log file name is required as input.")
    else:
        filename = args[0]
    if options.quiet:
        options.verbose = False

    try:
        #if we're writing verbose output, let's open the specified file for writing
        if options.outverbose:
            outf = open(options.outverbose, 'wb')

        #the magic begins - open file as read-only, and binary mode due to Windows bug with special chars
        with open(filename, 'rb') as f:
            sitedata = {}
            assetdata = {}
            for line in f:
                #check to see if any regexes match in the current line of the log file
                ip = ipPattern.search(line)
                alive = alivePattern.search(line)
                dead = deadPattern.search(line)
                tcp_port = tcpPattern.search(line)
                udp_port = udpPattern.search(line)
                node_start = startPattern.search(line)
                node_end = endPattern.search(line)
                spider_start = spiderStartPattern.search(line)
                spider_end = spiderEndPattern.search(line)
                scan_start = scanStartPattern.search(line)
                scan_pause = scanPausePattern.search(line)
                scan_stop = scanStopPattern.search(line)
                system_fingerprint = sysFingerprintPattern.search(line)
                log_timestamp = timePattern.search(line)
                site_name = sitePattern.search(line)
                spider_summary = spiderSummaryPattern.search(line)
                vuln = vulnerablePattern.search(line)

                if log_timestamp:
                    timestamp = log_timestamp.group()

                if site_name:
                    sitename = site_name.group(1)
                    if sitename in sitedata:
                        sitedata[sitename]['last_timestamp'] = timestamp
                    else:
                        sitedata[sitename] = init_site(timestamp)
                        sitedata[sitename]['first_timestamp'] = timestamp
                        verbose_output(sitename, 'found in log', timestamp)
    
                if scan_start:                                        
                    verbose_output(sitename, 'scan STARTED', timestamp)
                    if sitename in sitedata:
                        sitedata[sitename]['scan_start'].append(timestamp)
                    else:
                        sitedata[sitename] = init_site(timestamp)
                        sitedata[sitename]['scan_start'].append(timestamp)

                if scan_pause:
                    verbose_output(sitename, 'scan PAUSED', timestamp)
                    if sitename in sitedata:
                        sitedata[sitename]['scan_pause'].append(timestamp)
                    else:
                        sitedata[sitename] = init_site(timestamp)
                        sitedata[sitename]['scan_pause'].append(timestamp)
                    
                if scan_stop:
                    verbose_output(sitename, 'scan STOPPED', timestamp)
                    if sitename in sitedata:
                        sitedata[sitename]['scan_stop'].append(timestamp)
                        sitedata[sitename]['completed'] = 'Yes'
                    else:
                        sitedata[sitename] = init_site(timestamp)
                        sitedata[sitename]['scan_stop'].append(timestamp)
                        sitedata[sitename]['completed'] = 'Yes'
                    
                if ip:
                    ip = ip.group(1)
                    if ip in assetdata:
                        assetdata[ip]['last_timestamp'] = timestamp
                    elif not dead:
                        assetdata[ip] = init_asset(sitename, timestamp)
                        if not alive:
                                verbose_output(sitename, 'Asset {0} found in log before ALIVE status'.format(ip), timestamp)

                if alive:
                    if ip in assetdata:
                        assetdata[ip]['alive'] = timestamp
                        verbose_output(sitename, 'Asset {0} found ALIVE'.format(ip), timestamp)                
                    else:
                        assetdata[ip] = init_asset(sitename, timestamp)
                        assetdata[ip]['alive'] = timestamp
                        verbose_output(sitename, 'Asset {0} found ALIVE'.format(ip), timestamp)

                if dead:
                    sitedata[sitename]['dead_ips'].append(ip)                
                    verbose_output(sitename, 'Asset {0} found DEAD'.format(ip), timestamp)

                if tcp_port:
                    tcpport = tcp_port.group('port')
                    tcpreason = tcp_port.group('reason')
                    assetdata[ip]['tcpportlist'].append(tcpport)
                    assetdata[ip]['tcpports'] = len(assetdata[ip]['tcpportlist'])
                    if not assetdata[ip]['tcptime']:
                        assetdata[ip]['tcptime'] = timestamp
                    verbose_output(sitename, 'Asset {0} found open TCP port {1} reason: {2}'.format(ip, tcpport, tcpreason),timestamp)

                if udp_port:
                    udpport = udp_port.group('port')
                    udpreason = udp_port.group('reason')
                    assetdata[ip]['udpportlist'].append(udpport)
                    assetdata[ip]['udpports'] = len(assetdata[ip]['udpportlist'])
                    if not assetdata[ip]['udptime']:
                        assetdata[ip]['udptime'] = timestamp
                    verbose_output(sitename, 'Asset {0} found open UDP port {1} reason: {2}'.format(ip, udpport, udpreason),timestamp)

                if node_start:
                    if ip and log_timestamp:
                        assetdata[ip]['nodestart'] = timestamp
                        verbose_output(sitename, 'Asset {0} node scan started'.format(ip), timestamp)

                if node_end:
                    if ip and log_timestamp:
                        assetdata[ip]['nodeend'] = timestamp
                        assetdata[ip]['completed'] = 'Yes'
                        verbose_output(sitename, 'Asset {0} node scan ended'.format(ip), timestamp)                      

                if spider_start:
                    if ip and log_timestamp:                        
                        if not assetdata[ip]['spiderstart']:
                            assetdata[ip]['spiderstart'] = timestamp
                            verbose_output(sitename, 'Asset {0} web spider started'.format(ip), timestamp)

                if spider_end:
                    if ip and log_timestamp:
                        assetdata[ip]['spiderend'] = timestamp
                        verbose_output(sitename, 'Asset {0} web spider ended'.format(ip), timestamp)

                if spider_summary:
                    if ip and log_timestamp:
                        if not assetdata[ip]['urls'] or assetdata[ip]['urls'] < spider_summary.group('urls'):
                            assetdata[ip]['urls'] = spider_summary.group('urls')
                if vuln:
                    if ip:
                        assetdata[ip]['vulns'] += 1

                if system_fingerprint:
                    if ip:
                        assetdata[ip]['fingerprint_certainty'] = system_fingerprint.group('certainty')
                        verbose_output(sitename, 'Asset {0} fingerprint certainty: {1}'.format(ip, system_fingerprint.group('certainty')), timestamp)

    except KeyboardInterrupt:
        print '\nExit: Interrupted by user.'
        exit(0)

    #open a specified plaintext file for writing
    if not options.outverbose:
        if options.outfile:
            outf = open(options.outfile, 'wb')

    #todo: implement CSV output (in particular, summary csv file)
    #open a specified CSV file for writing
    if options.csvfile:
        #outcsvsum = ''.join((options.csvfile.rstrip('.csv'),'_summary.csv'))
        outc = open(options.csvfile, 'wb')
        #outcs = open(outcsvsum, 'w')
        csvwriter = csv.writer(outc)
        #csvsumwriter = csv.writer(outcs)
        csvwriter.writerow(headers)
        #csvsumwriter.write(summary_headers)

    try:
        #total up scan durations for each site found in scan log
        for site in sitedata:
            starts = len(sitedata[site]['scan_start'])
            pauses = len(sitedata[site]['scan_pause'])
            stops = len(sitedata[site]['scan_stop'])

            if pauses >= 1:
                if starts >= pauses:
                    for start, pause in izip(sitedata[site]['scan_start'], sitedata[site]['scan_pause']):
                        sitedata[site]['scan_durations'].append(calc_duration(start, pause))                    

            if stops <= 0:
                sitedata[site]['scan_stop'].append(sitedata[site]['last_timestamp'])

            sitedata[site]['scan_durations'].append(calc_duration(sitedata[site]['scan_start'][starts - 1], sitedata[site]['scan_stop'][stops - 1]))

            total = timedelta(0)
            for duration in sitedata[site]['scan_durations']:
                total = total + duration

            sitedata[site]['scan_total_duration'] = total
            longestscan = {'site':'','asset':'','time':timedelta(0)}
            shortestscan = {'site':'','asset':'','time':timedelta(365)}
            alivecount = 0
            scannedcount = 0
            node_times = []
            discovery_times = []
            spider_times = []

            for asset in assetdata:
                if assetdata[asset]['sitename'] == site:
                    if assetdata[asset]['nodeend'] and assetdata[asset]['nodestart']:
                        assetdata[asset]['nodetime'] = calc_duration(assetdata[asset]['nodestart'], assetdata[asset]['nodeend'])
                        node_times.append(assetdata[asset]['nodetime'])
                    elif assetdata[asset]['nodestart']:
                        assetdata[asset]['nodetime'] = calc_duration(assetdata[asset]['nodestart'], assetdata[asset]['last_timestamp'])
                        node_times.append(assetdata[asset]['nodetime'])
                    else:
                        assetdata[asset]['nodetime'] = 'Unknown'

                    if assetdata[asset]['alive']:
                        assetdata[asset]['discoverytime'] = calc_duration(sitedata[site]['scan_start'][0], assetdata[asset]['alive'])
                        discovery_times.append(assetdata[asset]['discoverytime'])                    
                    elif assetdata[asset]['tcptime']:
                        assetdata[asset]['discoverytime'] = calc_duration(sitedata[site]['scan_start'][0], assetdata[asset]['tcptime'])
                        discovery_times.append(assetdata[asset]['discoverytime'])                    
                    elif assetdata[asset]['udptime']:
                        assetdata[asset]['discoverytime'] = calc_duration(sitedata[site]['scan_start'][0], assetdata[asset]['udptime'])
                        discovery_times.append(assetdata[asset]['discoverytime'])                    
                    else:
                        assetdata[asset]['discoverytime'] = 'Unknown'

                    if assetdata[asset]['spiderend'] and assetdata[asset]['spiderstart']:
                        assetdata[asset]['spidertime'] = calc_duration(assetdata[asset]['spiderstart'], assetdata[asset]['spiderend'])
                        spider_times.append(assetdata[asset]['spidertime'])
                    elif assetdata[asset]['spiderstart']:
                        assetdata[asset]['spidertime'] = calc_duration(assetdata[asset]['spiderstart'], assetdata[asset]['last_timestamp'])
                        spider_times.append(assetdata[asset]['spidertime'])
                    else:
                        assetdata[asset]['spidertime'] = 'Unknown'

                    if assetdata[asset]['discoverytime'] != 'Unknown' and assetdata[asset]['nodetime'] != 'Unknown':
                        assetdata[asset]['totaltime'] = assetdata[asset]['discoverytime'] + assetdata[asset]['nodetime']
                    else:
                        assetdata[asset]['totaltime'] = 'Unknown'

                    if assetdata[asset]['totaltime'] != 'Unknown' and assetdata[asset]['totaltime'] > longestscan['time']:
                        longestscan['site'] = assetdata[asset]['sitename']
                        longestscan['asset'] = asset
                        longestscan['time'] = assetdata[asset]['totaltime']

                    if assetdata[asset]['totaltime'] != 'Unknown' and assetdata[asset]['totaltime'] < shortestscan['time']:
                        shortestscan['site'] = assetdata[asset]['sitename']
                        shortestscan['asset'] = asset
                        shortestscan['time'] = assetdata[asset]['totaltime']

                    if assetdata[asset]['alive']:
                        alivecount += 1

                    if assetdata[asset]['nodeend']:
                        scannedcount += 1

                    #outtext = 'Site: %s | Asset: %s | Open Ports: %s | Discovery Time: %s | Spider Time: %s | Node Time: %s | Total Time: %s' % (assetdata[asset]['sitename'],asset.ljust(15), str(assetdata[asset]['tcpports']).ljust(5), str(assetdata[asset]['discoverytime']).ljust(17), str(assetdata[asset]['spidertime']).ljust(17), str(assetdata[asset]['nodetime']).ljust(17), str(assetdata[asset]['totaltime']))

                    if not options.quiet:
                        #print outtext
                        pass

                    if options.outfile:
                        #outf.write(outtext + '\n')
                        pass

                    if options.csvfile:
                        csvwriter.writerow((assetdata[asset]['sitename'], asset, assetdata[asset]['tcpports'], assetdata[asset]['udpports'], str(assetdata[asset]['discoverytime']), str(assetdata[asset]['urls']), str(assetdata[asset]['spidertime']), str(assetdata[asset]['nodetime']), str(assetdata[asset]['totaltime']), assetdata[asset]['completed'], ', '.join(assetdata[asset]['tcpportlist']), ', '.join(assetdata[asset]['udpportlist']), str(assetdata[asset]['vulns']), str(assetdata[asset]['fingerprint_certainty']) ))


            if discovery_times:
                average_discovery_time = sum(discovery_times, default_timestamp) / len(discovery_times)
            else:
                average_discovery_time = 'Unknown'
            if node_times:
                average_node_time = sum(node_times, default_timestamp) / len(node_times)
            else:
                average_node_time = 'Unknown'
            if spider_times:
                average_spider_time = sum(spider_times, default_timestamp) / len(spider_times)
            else:
                average_spider_time = 'Unknown'

            print '\nSummary for [Site: %s]' % site
            print 'Total assets logged: %i' % ((len(assetdata)+len(sitedata[sitename]['dead_ips'])))
            print 'Total assets alive: %i' % (alivecount)
            print 'Total assets scanned (complete): %i' % (scannedcount)
            print 'Total scan time: %s' % total
            print 'Scan completed: %s' % sitedata[site]['completed']
            if longestscan['site']:
                print 'Most scan time: %s @ %s' % (longestscan['asset'], longestscan['time'])
            if shortestscan['site']:
                print 'Least scan time: %s @ %s \n' % (shortestscan['asset'], shortestscan['time'])
            print 'Average discovery time: %s' % average_discovery_time
            print 'Average node time: %s' % average_node_time
            print 'Average web spider time: %s' % average_spider_time

        #todo: make sure each site detected can be summarized
        #csvsumwriter.write(site, logged_assets, live_assets, scanned_assets, total_duration, high_duration_asset, high_duration, low_duration_asset, low_duration)

    except KeyboardInterrupt:
        if options.outfile:
            outf.close()
        if options.csvfile:
            outc.close()
            #outcs.close()
        print '\nExit: Interrupted by user'
        exit(0)
        #close said file after writing
        if options.outfile:
            outf.close()
        if options.csvfile:
            outc.close()
            #outcs.close()


if __name__ == '__main__':
    main()