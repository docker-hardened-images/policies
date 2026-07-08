# METADATA
# title: No fixable vulnerabilities past their remediation SLA
# description: Flags packages with a fixable CVE whose remediation SLA has elapsed. SLAs vary by severity, with a shorter SLA for CISA KEV-listed vulnerabilities. Only vulnerabilities that have a fix available are considered.
# organizations:
# - Docker
# authors:
# - Christian Dupuis <cd@docker.com>
# custom:
#   name: fixable-vulnerabilities
#   result_type: vulnerability
#   weight: 10
#   not_compliant_title: Fixable vulnerabilities past remediation SLA
#   details_order:
#   - purl
#   - vulnerability
#   - severity
#   - fixedBy
#   - cvssScore
#   - sla
package docker.scout

import rego.v1

default pass := false

pass if {
	count(violation) == 0
}

day_ns := (24 * 3600) * 1000000000

# Remediation SLA in days per severity. The SLA is the number of days after a
# CVE is disclosed within which a fix must be applied. Only fixable
# vulnerabilities are considered. Configurable via --policy-config:
# {"slas": {"CRITICAL": 7, "HIGH": 7, "MEDIUM": 30, "LOW": 30, "UNSPECIFIED": 30}}
default_slas := {
	"CRITICAL": 7,
	"HIGH": 7,
	"MEDIUM": 30,
	"LOW": 30,
	"UNSPECIFIED": 30,
}

slas := object.get(data.config, "slas", default_slas)

# Remediation SLA in days for vulnerabilities listed in CISA's Known Exploited
# Vulnerabilities (KEV) catalog. Takes precedence over the severity SLA.
# Configurable via --policy-config: {"kev_sla_days": 1}
kev_sla_days := object.get(data.config, "kev_sla_days", 1)

# SLA in days applied when a vulnerability's severity is not present in the SLA
# map. Configurable via --policy-config: {"default_sla_days": 30}
default_sla_days := object.get(data.config, "default_sla_days", 30)

# Optional allowlist of PURL package types to consider (e.g. "deb", "npm").
# When empty (the default) packages of every type are considered.
# Configurable via --policy-config: {"package_types": ["deb", "rpm"]}
package_types := object.get(data.config, "package_types", [])

# VEX statuses that exclude a vulnerability from the policy. By default both
# "not_affected" and "under_investigation" statements suppress a finding.
# Configurable via --policy-config: {"excluded_vex_statuses": ["not_affected"]}
excluded_vex_statuses := object.get(data.config, "excluded_vex_statuses", ["not_affected", "under_investigation"])

violation contains v if {
	some entry in oci.referrer("https://scout.docker.com/vulnerabilities/v0.1").statement.predicate
	some cve in entry.vulnerabilities

	cve.fixed_by
	package_type_satisfied(entry.purl)
	not vex_excluded(cve, entry.purl)
	sla_breached(cve)

	v := {
		"message": sprintf("Package %s is affected by %s past its remediation SLA", [entry.purl, cve.source_id]),
		"detail": {
			"purl": entry.purl,
			"vulnerability": cve.source_id,
			"severity": severity(cve),
			"fixedBy": object.get(cve, "fixed_by", ""),
			"cvssScore": sprintf("%.1f", [object.get(object.get(cve, "cvss", {}), "score", 0)]),
			"sla": sla_label(cve),
		},
	}
}

# Normalized severity for a vulnerability, defaulting to UNSPECIFIED.
severity(cve) := upper(object.get(object.get(cve, "cvss", {}), "severity", "UNSPECIFIED"))

# Remediation SLA (in days) for a vulnerability. KEV-listed vulnerabilities use
# the KEV SLA; everything else uses the SLA for its severity.
sla_days(cve) := kev_sla_days if {
	cve.cisa_exploited
}

sla_days(cve) := object.get(slas, severity(cve), default_sla_days) if {
	not cve.cisa_exploited
}

# Human-readable label describing the SLA applied to a vulnerability.
sla_label(cve) := sprintf("%v days (KEV)", [sla_days(cve)]) if {
	cve.cisa_exploited
}

sla_label(cve) := sprintf("%v days", [sla_days(cve)]) if {
	not cve.cisa_exploited
}

# A vulnerability breaches its SLA when it has been public for at least as many
# days as its SLA. A missing or unparseable disclosure date is treated as a
# breach, since compliance with the SLA cannot be demonstrated.
sla_breached(cve) if {
	cve.published_at != ""
	published := time.parse_rfc3339_ns(cve.published_at)
	time.now_ns() - published >= sla_days(cve) * day_ns
}

sla_breached(cve) if {
	object.get(cve, "published_at", "") == ""
}

# A package satisfies the package-type filter when no types are configured, or
# when its PURL type is in the configured list.
package_type_satisfied(_) if {
	count(package_types) == 0
}

package_type_satisfied(purl) if {
	count(package_types) > 0
	scout.parse_purl(purl).type in package_types
}

vex_excluded(cve, purl) if {
	vex := oci.referrer("https://openvex.dev/ns/v0.2.0").statement.predicate
	some stmt in vex.statements
	stmt.vulnerability.name == cve.source_id
	some product in stmt.products
	product["@id"] == purl
	stmt.status in excluded_vex_statuses
}
