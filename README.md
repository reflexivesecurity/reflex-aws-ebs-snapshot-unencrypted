# reflex-aws-ebs-snapshot-unencrypted
A Reflex Rule for detecting unencrypted EBS snapshots.

## Usage
To use this rule either add it to your `reflex.yaml` configuration file:  
```
rules:
  - reflex-aws-ebs-snapshot-unencrypted:
      version: latest
```

or add it directly to your Terraform:  
```
...

module "reflex-aws-ebs-snapshot-unencrypted" {
  source           = "github.com/cloudmitigator/reflex-aws-ebs-snapshot-unencrypted"
}

...
```

## License
This Reflex rule is made available under the MPL 2.0 license. For more information view the [LICENSE](https://github.com/cloudmitigator/reflex-aws-ebs-snapshot-unencrypted/blob/master/LICENSE)
