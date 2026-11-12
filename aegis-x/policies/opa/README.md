# Policy-as-code

This directory will hold Conftest/OPA policies for Terraform plan JSON and normalized AEGIS-X events.

Initial policy requirements:
- Deny public object-storage exposure unless a documented exception is approved.
- Deny unencrypted storage and databases.
- Deny wildcard administrative grants outside explicit break-glass roles.
- Require audit logging, ownership tags, and approved regions.
- Require private network access for sensitive data services where supported.
- Require retention and backup policies for classified data.

Policies must be tested against both positive and negative fixtures before CI enforcement. Do not treat a policy pack as a substitute for provider-native controls or human review.
