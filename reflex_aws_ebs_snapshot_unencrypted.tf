module "reflex_aws_ebs_snapshot_unencrypted" {
  source           = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe_lambda?ref=v0.5.8"
  rule_name        = "EBSSnapshotUnencrypted"
  rule_description = "A Reflex Rule for detecting unencrypted EBS snapshots."

  event_pattern = <<PATTERN
{
  "source": [
    "aws.ec2"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "ec2.amazonaws.com"
    ],
    "eventName": [
      "CreateSnapshot",
      "CopySnapshot"
    ]
  }
}
PATTERN

  function_name   = "EBSSnapshotUnencrypted"
  source_code_dir = "${path.module}/source"
  handler         = "reflex_aws_ebs_snapshot_unencrypted.lambda_handler"
  lambda_runtime  = "python3.7"
  environment_variable_map = {
    SNS_TOPIC = var.sns_topic_arn
  }
  custom_lambda_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:DescribeSnapshots"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

  queue_name    = "EBSSnapshotUnencrypted"
  delay_seconds = 0

  target_id = "EBSSnapshotUnencrypted"

  sns_topic_arn  = var.sns_topic_arn
  sqs_kms_key_id = var.reflex_kms_key_id
}
