# OPA path: /v1/data/aws/s3/compliance/deny
# Input: CloudTrail-like event JSON as the request `input` document
#   (middleware POSTs {"input": <CloudAuditEvent>}).
#
# When no deny rules match, `deny` is undefined / empty → allow.
# When a rule matches, `deny` is a non-empty set of violation messages.
package aws.s3.compliance

import rego.v1

deny contains msg if {
	input.eventName == "CreateBucket"
	input.requestParameters.acl == "public-read"
	user := object.get(input.userIdentity, "userName", "unknown")
	msg := sprintf(
		"S3 compliance violation: user '%s' attempted CreateBucket with acl=public-read",
		[user],
	)
}
