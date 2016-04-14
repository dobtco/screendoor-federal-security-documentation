SSP
---

AC-2	Account Management

- All requests are authorized
- Permissions assigned by role
- New accounts can be created by administrators
- Only administrators can change permissions
- Administrators can remove accounts
- No group credentials


AC-3	Access Enforcement

narrative: "18F information systems enforces approved authorizations for logical\
  \ access to information and system resources in accordance with the 18F access\
  \ control policy Section 3 Access Enforcement which states:\n  * 18F must enforce\
  \ approved authorizations for logical access to its information systems in accordance\
  \ with all applicable Federal, and 18F policies.\n  * 18F must provide access\
  \ enforcement through the use of access control lists, access control matrices,\
  \ cryptography) to control access between users (or processes acting on behalf\
  \ of users) and objects (e.g., devices, files, records, processes, programs, domains)\
  \ in the information system.\n  * 18F must employ access enforcement mechanisms\
  \ at the application level, when necessary, to provide increased information security\
  \ for the organization.\n"


AC-6	Least Privilege
narrative: "18F restricts privileged accounts such as administrator and root access\
  \ accounts to designated members within the18F Devops and SecOps teams. Within\
  \ the virtual infrastructure the admin account is not used for privileged access.\
  \ It\u2019s only used for billing and metrics.\n"

AU-2	Audit Events

narrative: 'The Devops and SecOps teams review all events that can be audited on
  a real time basis using its event and monitoring solution for Cloud.Gov and through
  captured user and event api calls within its virtual infrastructure.

AU-6	Audit Review, Analysis and Reporting

narrative: "Audit Monitoring, Analysis and Reporting\n * 18F establishes processes\
  \ for regularly reviewing audit log information, and reporting security issues\
  \ if discovered. Reviews will occur at a minimum of weekly. These processes should\
  \ be integrated with processes for incident response, in order to ensure standardization\
  \ and cross-functional collaboration\n * 18F employs automated mechanisms to integrate\
  \ audit monitoring, analysis and reporting into an overall process for investigation\
  \ and response to suspicious activities.\n * 18F employs automated mechanisms\
  \ to immediately alert security personnel of inappropriate or unusual activities\
  \ that have security implications.\n"

  narrative: "#### a  \nAWS Auditable Events:\nDevOps and SecOps teams will conduct\
    \ weekly manual and automated continuous audits of authorized accounts and configurations.\
    \ These audits will include but are not limited to:\nAdministrative Accounts\n\
    * Virtual Private Cloud (VPC)\n* Elastic Compute Cloud (EC2)\n* Simple Storage\
    \ Service (S3)\n* Identity and Access Management (IAM)\n* Elastic Block Store\
    \ (EBS)\n\n\nCloud Foundry Auditable Events:\nBy default, Loggregator streams\
    \ logs to a terminal. 18F will drain logs to a third-party log management service\
    \ such as ELK and AWS CloudTrail\nCloud Foundry logs are captured in multiple\
    \ tables and log files. These will be reviewed weekly and if discovery of anomalous\
    \ audit log content which appears to indicate a breach are handled according to\
    \ the GSA Security Incident Handling Guide: CIO IT Security 01-02 Revision 7 (August\
    \ 18, 2009) requirements.\n  \n#### b  \nWhen a credible source to the GSA Agency\
    \ provides information that causes reason to enhance audit activities, develop\
    \ and implement an enhanced auditing use-case that will adequately enhance auditing\
    \ practices in a fashion necessary per the identified threat and following the\
    \ Incident Reporting Procedures in GSA IT Security Procedural Guide 01-02 (04/07/2015),\
    \ Incident Response. The GSA Agency may also, through analysis pertaining to the\
    \ GSA Agency environment provide additional audit measures that will require an\
    \ increase in review, analysis, and reporting for a necessary.\nUpon implementation,\
    \ 18F will monitor information security news and alerts for indications of a need\
    \ to heighten information system security monitoring.\n  \n"

CA-8	Penetration Testing

For compliance with NIST Publication 800-53 CA-8, Parameter 1 Penetration Testing
of all 18F Infrastructure and Application Components will occur annually. Parameter
2 Penetration Testing of Publicly Accessible Infrastructure will be performed
on the direction of the 18F .

CM-2	Baseline Configuration

- We use AWS Ubuntu 14 as baseline

CM-3	Configuration Change Control

- nginx config is in version control
- changes are made on staging before production

CM-6	Configuration Settings

CM-8	Information System Component Inventory

- AWS dashboard is used to inventory and monitor resources
- TrustedAdvisor is used to find unutilized resources


IA-2	Identification and Authentication (Organizational Users)

- 2-factor authentication is supported on all user accounts

IA-2 (1)	Identification and Authentication (Organizational Users)  Network Access to Privileged Accounts
IA-2 (2)	Identification and Authentication (Organizational Users)  Network Access to Non-Privileged Accounts
IA-2 (12)	Identification and Authentication  Acceptance of PIV Credentials


PL-8	Information Security Architecture

tl;dr write this documentation, keep it updated

narrative: "#### a  \n18F has developed the system security plan (SSP) for Cloud\
  \ Foundry PaaS containing the information security architecture for the information\
  \ system that:\nDescribes the overall philosophy, requirements, and approach to\
  \ be taken with regard to protecting the confidentiality, integrity, and availability\
  \ of organizational information\nDescribes how the information security architecture\
  \ is integrated into and supports the enterprise architecture\nDescribes any information\
  \ security assumptions about, and dependencies on, external services\n  \n####\
  \ b  \n18F Reviews and updates the information security architecture within the\
  \ System Security plans and the 18F GitHub repository on an annual basis or when\
  \ a significant change takes place to reflect updates in the enterprise architecture.\n\
  Due to the dynamic and elastic nature of cloud computing,  18F monitors real-time\
  \ updates of its information security architecture using its infrastructure management\
  \  and visual security consoles.\n  \n#### c  \n18F ensures that planned information\
  \ security architecture changes are reflected in the security plan and organizational\
  \ procurements/acquisitions.\n18F follows the risk management framework (RMF)\
  \ which includes conducting annual risk assessments for its information systems\
  \ and infrastructure. Any changes are then updated in systems security plans,\
  \ plan of actions and milestones POA&Ms, security assessment reports (SAR)\n \

RA-5	Vulnerability Scanning

tl;dr continuous OS scanning, code scanning on every code release
- OWASP top 10

narrative: "#### a  \n18F Conducts monthly Operating System (OS) and web application\
  \ scanning; quarterly database scanning; and, OS and Web application scanning\
  \ with every code release. 18F conducts internal vulnerabilty scanning of its\
  \ VPC and private subnets within the 18F Virtual Private Cloud.\n  \n#### b  \n\
  18F vulnerabilty scanning toos utilize techniques that promote interoperability\
  \ such as Common Vulnerability Scoring System v2 (CVSS2), Common Platform Enumeration\
  \ (CPE), and Common Vulnerability Enumeration (CVE) and OWASP TOP 10 vulnerabilities.\n\
  \  \n#### c  \n18F Analyzes vulnerability scan reports from its vulnerabilty scanning\
  \ tools assessments at least weekly and appropriate actions taken on discovery\
  \ of vulnerabilities within the 18F Cloud Infrastructure and applications and\
  \ from security control assessments conducted on its information systems.\n  \n\
  #### d  \nHigh-risk vulnerabilities are mitigated within thirty days (30); moderate\
  \ risk vulnerabilities mitigated within ninety days (90). If the recommended steps\
  \ will adversely impact functionality or performance, the ISSO/ISSM will reviews\
  \ changes and mitigating controls with 18F DevOps as well as the Cloud Foundry\
  \ system owners.\n  \n#### e  \n18F shares information obtained from the vulnerability\
  \ scanning process and security control assessments with designated System Owners,\
  \ DevOPs, GSA SecOps, ISSM and the Authorizing Official (AO) to help eliminate\
  \ similar vulnerabilities in other information systems (i.e., systemic weaknesses\
  \ or deficiencies).\n  \n"

SA-22	Unsupported System Components

- Don't use unsupported software
- Provide justification for continued use of unsupported software

SA-11 (1)	Developer Security Testing and Evaluation/ Static Code Analysis

- Brakeman / Codeclimate / Other static analysis

SC-7	Boundary Protection

- AWS VPC
-   narrative: "#### b  \n18F Implements subnetworks for publicly accessible system\
    \ components that are logically separated from internal organizational networks\n\


SC-13	Cryptographic Protection/ FIPS Validated Cryptography

- http -> https redirect
- ws -> wss redirect for websockets
- All traffic over public internet happens over https

SI-2	Flaw Remediation

- Patches automatically installed
- Patches are tested in staging for side-effects before going into production

narrative: "#### a  \n18F identifies all system flaws related to Cloud.gov, reports\
  \ system flaws to information system owners, Authorizing officials, DevOps and\
  \ SecOp  and corrects information system flaws that affect Cloud.Gov\nCloud Foundry\
  \ manages software vulnerability using releases and BOSH stemcells. New Cloud\
  \ Foundry releases are created with updates to address code issues, while new\
  \ stemcells are created with patches for the latest security fixes to address\
  \ any underlying operating system issues. New Cloud Foundry releases are located\
  \ at https://github.com/Cloud Foundry/cf-release.\n18F implemenets the release\
  \ of Cloud Foundy he what (or the software developer/vendor in the case of software\
  \ developed and maintained by a vendor/contractor) promptly installs newly released\
  \ security relevant patches and tests patches, for effectiveness and potential\
  \ side effects on information systems before installation.\n  \n"


  narrative: "#### b  \nTests software and firmware updates related to flaw remediation\
    \ for effectiveness and potential side effects before installation.\n  \n####\
    \ c  \nInstalls security-relevant software and firmware updates within 30 daysrelease\
    \ of updates of the release of the updates.\n  \n#### d  \n18F incorporates flaw\
    \ remediation into the its configuration management process. New versions of Cloud.gov\
    \ can easily recreated and deployed in the event of any system flaws.\n  \n"

SI-4	Information System Monitoring

- Constant monitoring
- AWS has physical and network level controls
- Monitoring within VPC?


narrative: "#### a  \nThe 18F DevOps and SecOps teams monitors the Cloud.Gov information\
  \ system to detect potential attacks and intrusions from internal and external\
  \ sources in accordance with the 18F System Information and Integrity Policy section\
  \ 3 - Information System monitoring, the FedRAMP Incident communication procedures\
  \ and GSA CIO-IT Security-08-39 section \u201CSystem Monitoring / Audit Record\
  \ Review \u201C for GSA specifc infomation systems\n  \n#### b  \n18F identifies\
  \ un-authorized access to the Cloud.Gov information system using   automated monitoring\
  \ tools within its virutal proviate cloud for monitoringing, log management and\
  \ event analysis. 18F monitors for attacks and indicators of potential attacks,\
  \  unauthorized local, network, and remote connections.\n  \n#### c  \nThe infrastructure\
  \ that hosts Cloud.Gov provides monitoring and intrusion detcetion of unsual activity\
  \ at  the phyical and network layers. 18F is responsible for monitoring everything\
  \ related to its virtual infrastructure and has deployed monitoring  and intrusion\
  \ dectction tools within its virtual private cloud to log and dectect malicious\
  \ activities to its information systems including Cloud.Gov.\n  \n#### d  \n18F\
  \ ensures intrusion and monitoring tools are protected  from unauthorized access\
  \ by only granting access to certian members from the DevOps and SecOps team.\
  \ All monitoring and intrusion information data is protected by limiting accounts\
  \ to authorized privileged users only and is maintained in secured repositories\
  \ for review by those members.\n  \n#### e  \nInformation system monitoring will\
  \ be heightened based on advisories from Pivitol, US-CERT Advisories, commercial\
  \ security communities, and other sources.\n  \n#### f  \nInformation system monitoring\
  \ will be conducted in accordance and compliance with 18F security policies and\
  \ all applicable laws, Executive Orders, directives, and regulations.\n  \n####\
  \ g  \n18F provides monitoring of all information system components in the event\
  \ of an event or incident, information will be provided as it is available.  Scheduled\
  \ reports will be provided for events such as after-hours administrative logins,\
  \ users being added to privileged groups, persistent malware detections, etc.\
  \ to designated members of the DevOps teams and SecOps teams as needed\n  \n"

SI-10	Information Input Validation

- Rails sanitizes data before making SQL queries
- User-inputs are sanitized before being rendered as HTML (sanitize gem)
- No manual override for sanitization
