# METADATA
# title: No high-profile vulnerabilities
# description: Checks for a curated list of well-known, high-impact CVEs.
# organizations:
# - Docker
# authors:
# - Christian Dupuis <cd@docker.com>
# custom:
#   name: high-profile-vulnerabilities
#   result_type: vulnerability
#   weight: 20
#   not_compliant_title: High-profile vulnerabilities found
#   details_order:
#   - purl
#   - vulnerability
#   - severity
#   - fixedBy
#   - cvssScore
package docker.scout

import rego.v1

default pass := false

pass if {
	count(violation) == 0
}

# Curated list of high-profile CVEs. Configurable via --policy-config:
# {"cves": ["CVE-2021-44228", ...]}
default_high_profile_cves := [
	"CVE-2014-0160", # Heartbleed
	"CVE-2014-6271", # Shellshock
	"CVE-2021-44228", # Log4Shell
	"CVE-2021-45046", # Log4j follow-up
	"CVE-2022-22965", # Spring4Shell
	"CVE-2023-38545", # curl SOCKS5 heap overflow
	"CVE-2023-44487", # HTTP/2 Rapid Reset
	"CVE-2024-3094", # XZ Utils backdoor
]

high_profile_cves := object.get(data.config, "cves", default_high_profile_cves)

# CVEs to exclude from causing a failure, removed from both the curated list and
# the CISA KEV match below. Configurable via --policy-config:
# {"ignored_cves": ["CVE-2023-44487"]}
ignored_cves := object.get(data.config, "ignored_cves", [])

# When enabled (the default) any vulnerability listed in CISA's Known Exploited
# Vulnerabilities Catalog also counts, in addition to the curated list.
# Configurable via --policy-config: {"include_cisa_kev": false}
include_cisa_kev := object.get(data.config, "include_cisa_kev", true)

violation contains v if {
	some entry in oci.referrer("https://scout.docker.com/vulnerabilities/v0.1").statement.predicate
	some cve in entry.vulnerabilities

	is_high_profile(cve)

	v := {
		"message": sprintf("Package %s is affected by high-profile vulnerability %s", [entry.purl, cve.source_id]),
		"detail": {
			"purl": entry.purl,
			"vulnerability": cve.source_id,
			"severity": object.get(cve.cvss, "severity", ""),
			"fixedBy": object.get(cve, "fixed_by", ""),
			"cvssScore": sprintf("%.1f", [object.get(cve.cvss, "score", 0)]),
		},
	}
}

# All identifiers a vulnerability is known by: its primary id plus any aliases.
# This lets the curated list match regardless of which id the scanner reports.
cve_ids(cve) := array.concat([cve.source_id], object.get(cve, "aliases", []))

# A vulnerability is ignored when any of its identifiers is on the ignore list.
cve_ignored(cve) if {
	some id in cve_ids(cve)
	id in ignored_cves
}

# A vulnerability is high-profile when it is on the curated list and not ignored.
is_high_profile(cve) if {
	not cve_ignored(cve)
	some id in cve_ids(cve)
	id in high_profile_cves
}

# ...or when CISA KEV matching is enabled and it is a known-exploited CVE.
is_high_profile(cve) if {
	include_cisa_kev
	cve.cisa_exploited
	not cve_ignored(cve)
}
