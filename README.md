Screendoor Federal Security Documentation
----

- This repository is a centralized location for Screendoor's security documentation as it pertains to the
- This is focused on SaaS screendoor. There is also on-prem Screendoor, which will be covered in another doc
- Screendoor has not gone through FedRAMP authorization process. The process was too lengthly / costly for our small organization. However, we are hosted on AWS which has been FedRAMPd, and our software meets the controls that are mentioned in Kurt's blogpost; https://gsablogs.gsa.gov/innovation/2014/12/10/it-security-security-in-an-agile-development-cloud-world-by-kurt-garbars/

## What is Screendoor?


## How is Screendoor built, and how does it store information?

- How it moves information around (cf https://github.com/houndci/hound/blob/master/doc/SECURITY.md)
- Network diagram

## FISMA Categorization

- Low. We almost never collect PII as per https://pages.18f.gov/before-you-ship/security/pii/

## Static scans

Screendoor is continuously scanned with Brakeman, a static code analysis tool for Ruby on Rails.

[View Screendoor's static scan report &rarr;](Static Scans)

## Dynamic scans

Screendoor was most recently scanned with HP Fortify On Demand.

[View Screendoor's dynamic scan report &rarr;](Dynamic Scans)

## System security plan

We have documented our compliance with the 24 NIST controls that are part of a "Lightweight ATO process", [as described by GSA CISO Kurt Gabars](https://gsablogs.gsa.gov/innovation/2014/12/10/it-security-security-in-an-agile-development-cloud-world-by-kurt-garbars/).

[View Screendoor's SSP &rarr;](SSP)

## References and attachments

- [AWS FedRAMP Compliance](https://aws.amazon.com/compliance/fedramp/)
- [USAID Privacy Threshold Analysis](USAID_PTA.pdf)
