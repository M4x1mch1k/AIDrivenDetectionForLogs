# OPA path: /v1/data/aws/iam_kms/compliance/deny
# Input: CloudTrail-like event JSON as the request `input` document
#   (middleware POSTs {"input": <CloudAuditEvent>}).
#
# When no deny rules match, `deny` is undefined / empty → allow.
# When a rule matches, `deny` is a non-empty set of violation messages.
package aws.iam_kms.compliance

import rego.v1

_privileged_users := {"root", "admin", "security-admin"}

deny contains msg if {
	input.eventName == "CreateAccessKey"
	user := object.get(input.userIdentity, "userName", "unknown")
	_privileged_users[user]
	status := object.get(input.requestParameters, "status", "")
	status == "Active"
	msg := sprintf(
		"IAM/KMS compliance violation: privileged user '%s' attempted CreateAccessKey with status=Active",
		[user],
	)
}

deny contains msg if {
	input.eventName == "PutBucketEncryption"
	user := object.get(input.userIdentity, "userName", "unknown")
	kms_key := object.get(input.requestParameters, "kmsKeyId", "")
	kms_missing := kms_key == ""
	kms_missing
	msg := sprintf(
		"IAM/KMS compliance violation: user '%s' attempted PutBucketEncryption without kmsKeyId",
		[user],
	)
}

deny contains msg if {
	input.eventName == "CreateDbInstance"
	user := object.get(input.userIdentity, "userName", "unknown")
	encrypted := object.get(input.requestParameters, "storageEncrypted", false)
	encrypted == false
	msg := sprintf(
		"IAM/KMS compliance violation: user '%s' attempted CreateDbInstance with storageEncrypted=false",
		[user],
	)
}

deny contains msg if {
	input.eventName == "CreateDbInstance"
	user := object.get(input.userIdentity, "userName", "unknown")
	kms_key := object.get(input.requestParameters, "kmsKeyId", "")
	kms_key == ""
	msg := sprintf(
		"IAM/KMS compliance violation: user '%s' attempted CreateDbInstance without kmsKeyId",
		[user],
	)
}
