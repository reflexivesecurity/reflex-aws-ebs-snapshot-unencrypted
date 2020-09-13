""" Module for EBSSnapshotUnencrypted """

import json
import os

import boto3
from reflex_core import AWSRule, subscription_confirmation


class EBSSnapshotUnencrypted(AWSRule):
    """ A Reflex Rule for detecting unencrypted EBS snapshots. """

    client = boto3.client("ec2")

    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        """ Extract required event data """
        self.event_name = event["detail"]["eventName"]
        self.snapshot_id = event["detail"]["responseElements"]["snapshotId"]

    def resource_compliant(self):
        """
        Determine if the resource is compliant with your rule.

        Return True if it is compliant, and False if it is not.
        """
        response = self.client.describe_snapshots(
            Filters=[{"Name": "snapshot-id", "Values": [self.snapshot_id]}]
        )
        snapshot = response["Snapshots"][0]

        return snapshot["Encrypted"]

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        return f"The EBS snapshot with ID {self.snapshot_id} is unencrypted."


def lambda_handler(event, _):
    """ Handles the incoming event """
    print(event)
    if subscription_confirmation.is_subscription_confirmation(event):
        subscription_confirmation.confirm_subscription(event)
        return
    rule = EBSSnapshotUnencrypted(json.loads(event["Records"][0]["body"]))
    rule.run_compliance_rule()
