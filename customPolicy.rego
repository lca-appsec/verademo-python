# METADATA
# title: Limit risk
# description: |
#   Block issues based on risk level.
package policy.v1

import data.phylum.level
import rego.v1

# METADATA
# title: risk level cannot exceed medium
deny contains issue if {
    some issue in data.issues
    issue.severity > level.MEDIUM
}