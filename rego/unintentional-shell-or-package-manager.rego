# METADATA
# title: Unintentional shell or package manager
# description: This policy checks that a DHI does not contain a shell or package manager that we don't explicitly install.
# organizations:
# - Docker
# authors:
# - Christian Dupuis <cd@docker.com>
# custom:
#   name: dhi-unintentional-shell-or-package-manager
#   result_type: generic
#   not_compliant_title: Unintentional shell or package manager detected
#   details_order:
#   - message
#   - package
package docker.scout

import rego.v1

shells := ["bash", "busybox"]

package_managers := ["apk-tools", "apt"]

package_types := ["apk", "deb"]

default pass := false

pass if {
	count(violation) == 0
}

labels := input.source.image.config.config.Labels

violation contains v if {
	labels["com.docker.dhi.shell"] == ""
	att := oci.referrer("https://spdx.dev/Document")
	artifacts := att.statement.predicate.packages
	some pkg in artifacts
	print(pkg.name)
	pkg.name in shells

	v := {
		"message": sprintf("Shell '%s' detected", [pkg.name]),
		"detail": {
			"message": sprintf("Shell '%s' detected", [pkg.name]),
			"package": pkg.externalRefs[0].referenceLocator,
		},
	}
}

violation contains v if {
	labels["com.docker.dhi.package-manager"] == ""
	att := oci.referrer("https://spdx.dev/Document")
	artifacts := att.statement.predicate.packages
	some pkg in artifacts
	pkg.name in package_managers

	v := {
		"message": sprintf("Package manager '%s' detected", [pkg.name]),
		"detail": {
			"message": sprintf("Package manager '%s' detected", [pkg.name]),
			"package": pkg.externalRefs[0].referenceLocator,
		},
	}
}
