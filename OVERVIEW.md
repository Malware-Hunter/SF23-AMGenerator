# AMGenerator


## Overview

![AMGenerator Overview](https://github.com/Malware-Hunter/SF23-AMGenerator/blob/main/images/amgenerator.pdf.png)

Sure, here's the text formatted in Markdown:

a) The initial phase involves data acquisition based on AndroZoo metadata, this repository houses a selected collection of applications.

- ➊ CSV file: This CSV file contains information specific to APKs.

b) After the acquisition, the extraction phase begins where the Androguard tool is used to extract features and metadata from the applications (APKs).

- ➋ features: JSON files are generated to encapsulate the extracted features (e.g., Permissions, intents, apicalls).
- ➌ Metadata: JSON files are created to store details related to metadata (e.g., apk name, package, API version).

c) After extraction, the labeling phase is initiated through the VirusTotal API which integrates several scanners designed to identify malware and other security vulnerabilities.

- ➍ JSON files: These files document scan reports provided by VirusTotal.

## Getting labeling data from VirusTotal

![AMGenerator Labeling data from VirusTotal](https://github.com/Malware-Hunter/SF23-AMGenerator/blob/main/images/labeling.pdf.png)
  

  
