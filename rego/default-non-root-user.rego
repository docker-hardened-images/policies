# METADATA
# title: No default root user for non-dev images
# description: This policy checks that the image doesn't run as root per default. This is only enforced for non-dev variants.
# organizations:
# - Docker
# authors:
# - Christian Dupuis <cd@docker.com>
# custom:
#   name: dhi-default-non-root-user
#   result_type: boolean
#   not_compliant_title: Non-dev image runs as the root user
#   details_order:
#   - user
#   - explicit
package docker.scout

import rego.v1

default pass := false

pass if {
	count(violation) == 0
}

user := input.source.image.config.config.User

tag := input.source.image.config.config.Labels["com.docker.dhi.version"]

isDev := endswith(tag, "-dev")

isSdk := contains(tag, "-sdk-")

name := input.source.image.name

isPkg := startswith(name, "dhi/pkg-")

violation contains v if {
	not user
	not isDev
	not isSdk
	not isPkg
	v := {
		"message": "No user defined in image definition",
		"detail": {
			"user": "root",
			"explicit": false,
		},
	}
}

violation contains v if {
	user == "root"
	not isDev
	not isSdk
	not isPkg
	v := {
		"message": "No non-root user defined in image definition",
		"detail": {
			"user": "root",
			"explicit": true,
		},
	}
}
