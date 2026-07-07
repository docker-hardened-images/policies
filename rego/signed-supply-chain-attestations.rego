# METADATA
# title: Signed supply chain attestations
# description: This policy checks that all required SSC attestations are available and signed by a trusted party.
# organizations:
# - Docker
# authors:
# - Christian Dupuis <cd@docker.com>
# custom:
#   name: dhi-signed-supply-chain-attestations
#   result_type: generic
#   not_compliant_title: Missing or unsigned supply chain attestations
#   details_order:
#   - predicate
#   - reason
package docker.scout

import rego.v1

default pass := false

pass if {
	count(violation) == 0
}

# Predicate types that must be present and signed by a trusted party.
required_predicate_types := [
	"https://spdx.dev/Document",
	"https://slsa.dev/provenance/v0.2",
]

violation contains v if {
	some predicate_type in required_predicate_types
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
	some predicate_type in required_predicate_types
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
	some predicate_type in required_predicate_types
	ref := oci.referrer(predicate_type)

	not ref.image

	v := {
		"message": sprintf("Predicate %s doesn't resolve to image ref", [predicate_type]),
		"detail": {
			"predicate": predicate_type,
			"reason": "doesn't resolve to image ref",
		},
	}
}

verify_opts := {
	"key_ref": "https://dhi.io/keyring/latest.pub",
	"ignore_sct": true,
	"ignore_tlog": true,
	"check_claims": true,
	"experimental_oci11": true,
}

# Image references of every required, resolvable attestation. These are verified
# together so their signatures are checked concurrently rather than one
# round-trip at a time.
required_images := [att.image |
	some predicate_type in required_predicate_types
	att := oci.referrer(predicate_type)
]

verify_results := cosign.verify_images(required_images, verify_opts)

violation contains v if {
	some predicate_type in required_predicate_types

	att := oci.referrer(predicate_type)

	res := verify_results[att.image]
	res.error

	v := {
		"message": sprintf("Signature of %s attestation failed verification", [predicate_type]),
		"detail": {
			"predicate": predicate_type,
			"reason": res.error,
		},
	}
}
