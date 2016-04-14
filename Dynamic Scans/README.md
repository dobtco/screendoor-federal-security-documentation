Dynamic scans
----

## Scan summary

- 4 issues classified as "Low"
- 1 issue classified as "Medium"
  - This issue is a false positive. The scan reports a non-SSL cookie being used, but upon further investigation, it was identifying a Google Analytics cookie. All cookies that Screendoor uses are set as "SSL only".
- 1 _false positive_ classified as "High"
  - This issue has been resolved. The scan reported Screendoor as supporting TLS 1.0, but Screendoor's SSL configuration has been updated and it now [receives an "A+" from SSL Labs](ssl-labs.png).

[View the report &rarr;](Screendoor Report 1.pdf)
