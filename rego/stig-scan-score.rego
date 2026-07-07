# METADATA
# title: STIG scan
# description: This policy checks that FIPS images reach the required STIG scan score. Only enforced for images that declare FIPS compliance.
# organizations:
# - Docker
# authors:
# - Christian Dupuis <cd@docker.com>
# custom:
#   name: dhi-stig-scan-score
#   result_type: generic
#   not_compliant_title: STIG scan score below target
#   details_order:
#   - predicate
#   - score
#   - reason
package docker.scout

import rego.v1

default pass := false

pass if {
	count(violation) == 0
}

predicate_type := "https://docker.com/dhi/stig/v0.1"

# Minimum STIG scan score (as a percentage) a FIPS image must reach.
# Configurable via --policy-config: {"target_score": 95}
target_score := object.get(data.config, "target_score", 100)

# Value of the compliance label, e.g. "fips,stig,cis". Empty when unset.
compliance := object.get(input.source.image.config.config.Labels, "com.docker.dhi.compliance", "")

# The policy only applies to images that declare FIPS compliance.
is_fips if {
	some entry in split(compliance, ",")
	trim_space(entry) == "fips"
}

violation contains v if {
	is_fips
	is_null(oci.referrer(predicate_type))

	v := {
		"message": sprintf("Required predicate %s missing", [predicate_type]),
		"detail": {
			"predicate": predicate_type,
			"score": "",
			"reason": "is missing",
		},
	}
}

violation contains v if {
	is_fips
	ref := oci.referrer(predicate_type)

	digests := [d |
		some sub in ref.statement.subject
		d := sprintf("sha256:%s", [sub.digest.sha256])
	]

	digest := input.source.image.digest
	not digest in digests

	v := {
		"message": sprintf("Predicate %s doesn't match subject %s", [predicate_type, digest]),
		"detail": {
			"predicate": predicate_type,
			"score": "",
			"reason": sprintf("doesn't match subject %s", [digest]),
		},
	}
}

# The STIG attestation predicate is an array of scanned profiles, each with a
# summary reporting the weighted OpenSCAP score (defaultScore) out of its
# maximum (maxDefaultScore). A profile is a violation when its normalized score
# is below the target.
violation contains v if {
	is_fips
	ref := oci.referrer(predicate_type)
	some profile in ref.statement.predicate

	percentage := (profile.summary.defaultScore / profile.summary.maxDefaultScore) * 100
	percentage < target_score

	v := {
		"message": sprintf("STIG profile %q scored %.2f%%, below the required %v%%", [profile.name, percentage, target_score]),
		"detail": {
			"predicate": predicate_type,
			"score": sprintf("%.2f%%", [percentage]),
			"reason": sprintf("profile %q below required %v%%", [profile.name, target_score]),
		},
	}
}
