##! This script detects large number of DNS NXDOMAIN replies.
##! It generates notices when (i) The number of NXDOMAIN replies
##! for a local DNS zone exceeds threshold; and (ii) When the
##! number of NXDOMAIN replies for a host, where the query does
##! not map to a local dns zone, exceeds a threshold 
@load base/frameworks/metrics

module DNSNXDomain;

export {
	redef enum Notice::Type += {
		## Indicates that the number of NXDOMAIN replies for a local 
		## DNS zone exceeded threshold
		DNS_Nxdomain_Local,
		## Indicates that the number of NXDOMAIN replies to a host for 
		## non-local DNS zone(s) exceeded threshold
		DNS_Nxdomain_External,
	};
	
	redef enum Metrics::ID += {
		## Metric to track DNS NXDOMAIN replies for local dns zone
		DNS_NXDOMAIN_LOCAL,
		## Metric to track DNS NXDOMAIN replies to a host (for non-local dns zones)
		DNS_NXDOMAIN_EXTERNAL,
	};
	
	## Defines the threshold for DNS NXDOMAIN replies where the query 
	## was for a local dns zone
	const dns_nxdomain_local_threshold = 50 &redef;

	## Defines the threshold for DNS NXDOMAIN replies to a host 
	## where the query was for non-local dns zone(s)
	const dns_nxdomain_external_threshold = 50 &redef;

	## Interval at which to watch for the
	## :bro:id:`DNSNXDomain::dns_nxdomain_local_threshold` variable to be crossed.
	## At the end of each interval the counter is reset.
	const dns_nxdomain_local_interval = 5min &redef;

	## Interval at which to watch for the
	## :bro:id:`DNSNXDomain::dns_local_nxdomain_threshold` variable to be crossed.
	## At the end of each interval the counter is reset.
	const dns_nxdomain_external_interval = 5min &redef;
}

## Table to contain pattern-equivalent of dns zone strings
## in Site::local_zones
global zone_patterns: table[count] of pattern;

event bro_init() &priority=3
	{
	local idx = 0;
	for ( zone in Site::local_zones )
		{
		local zone_p = string_to_pattern( zone, T );
		zone_patterns[++idx] = zone_p;	
		}

	# Add filters to the metrics so that the metrics framework knows how to 
	# determine when it looks like an actual attack and how to respond when
	# thresholds are crossed.
	
	Metrics::add_filter(DNS_NXDOMAIN_LOCAL, [$log=F,
	                                   $notice_threshold=dns_nxdomain_local_threshold,
	                                   $break_interval=dns_nxdomain_local_interval,
	                                   $note=DNS_Nxdomain_Local]);
	Metrics::add_filter(DNS_NXDOMAIN_EXTERNAL, [$log=F,
	                                 $notice_threshold=dns_nxdomain_external_threshold,
	                                 $break_interval=dns_nxdomain_external_interval,
	                                 $note=DNS_Nxdomain_External]);
	}

## Tracks failed DNS queries
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	if ( msg$rcode==3 ) #rcode=3 for NXDOMAIN
		{
		if ( c$dns$qtype_name=="AAAA" || c$dns$qtype_name=="A" )
			{
			local query = c$dns$query;
			local dns_zone = "";

			# Is the query for our DNS zone
			local our_zone = F;
			for ( idx in zone_patterns )
				{
				local tokens = split( query, zone_patterns[idx] );
				local len_tokens = length( tokens );					
				
				if ( tokens[len_tokens] == "" ) # if a pattern occurs at the end of a string, 
								# the last token will always be ""  
					{
					our_zone = T;
					dns_zone = find_last( query, zone_patterns[idx] ) ;
					break;
					}
				}

			if ( our_zone )
				{
				Metrics::add_data(DNS_NXDOMAIN_LOCAL, [ $str = dns_zone ], 1);
				}
			else
				Metrics::add_data(DNS_NXDOMAIN_EXTERNAL, [ $host = c$id$orig_h ], 1);
			}
		}
	}

