# ADGenerator - Android Data Generator

## Environment

The tool has been tested in the following environments:

**Ubuntu 20.04**

- Kernel = `Linux version 5.4.0-120-generic (buildd@lcy02-amd64-006) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #136-Ubuntu SMP Fri Jun 10 13:40:48 UTC 2022`
- Python = `Python 3.8.10`

## Requirements
- Installing Python requirements:

    ```sh
    $ pip install -r requirements.txt
    ```


### 📌 Available Arguments:

    ```
    usage: adgen.py [-h] --file FILE [--download] [--download_dir PATH] [--androzoo-key KEY] [--num-parallel-download INT] [--extraction]
                    [--num-parallel-extraction INT] [--label] [--vt-key KEY] [--output-data PATH]

    Show Help:
      -h, --help            Show Help Message And Exit

    ADGen Parameters:
      --file FILE           File With a List of APKs SHA256 (One Per Line)
      --download            Download APK files
      --download_dir PATH   Directory to/from Downloads
      --androzoo-key KEY, -azk KEY
                            Androzoo API Key
      --num-parallel-download INT, -npd INT
                            Number of Parallel Downloads
      --extraction          APK Metadata and Features Extraction
      --num-parallel-extraction INT, -npe INT
                            Number of Parallel Process for Feature Extraction
      --label               VirusTotal Labelling
      --vt-key KEY, -vtk KEY
                            VirusTotal's API Key
      --output-data PATH    Data Output Directory
    ```
