# METADATA
# title: No embedded secrets
# description: This policy checks that no secrets are embedded in the image.
# organizations:
# - Docker
# authors:
# - Christian Dupuis <cd@docker.com>
# custom:
#   name: dhi-no-embedded-secrets
#   result_type: generic
#   not_compliant_title: Image contains embedded secrets
#   details_order:
#   - predicate
#   - reason
package docker.scout

import rego.v1

default pass := false

pass if {
	count(violation) == 0
}

predicate_type := "https://scout.docker.com/secrets/v0.1"

violation contains v if {
	is_null(oci.referrer(predicate_type))

	v := {
		"message": sprintf("Required predicate %s missing", [predicate_type]),
		"detail": {
			"predicate": predicate_type,
			"reason": "is missing",
		},
	}
}

violation contains v if {
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
			"reason": sprintf("doesn't match subject %s", [digest]),
		},
	}
}

violation contains v if {
	ref := oci.referrer(predicate_type)
	count(ref.statement.predicate) != 0

	v := {
		"message": "Image contains leaked secrets",
		"detail": {
			"predicate": predicate_type,
			"reason": "contains leaked secrets",
		},
	}
}
