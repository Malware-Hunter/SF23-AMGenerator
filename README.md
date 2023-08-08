# ADGenerator - Android Data Generator

### :gear: Environment

The tool has been tested in the following environments:

**Ubuntu 20.04**

- Kernel = `Linux version 5.4.0-120-generic (buildd@lcy02-amd64-006) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #136-Ubuntu SMP Fri Jun 10 13:40:48 UTC 2022`
- Python = `Python 3.8.10`


### :memo: Installing Python Requirements

    ```sh
    $ pip install -r requirements.txt
    ```

### :pushpin: Available Arguments:

    ```
    usage: adgen.py [-h] --file FILE [--download] [--download_dir PATH]
                    [--androzoo-key KEY] [--num-parallel-download INT]
                    [--extraction] [--num-parallel-extraction INT] [--label]
                    [--vt-key KEY] [--reanalyze-time INT] [--output-data PATH]

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
      --reanalyze-time INT, -rt INT
                            Time to Wait for Reanalysis (in Hours)
      --output-data PATH    Data Output Directory
    ```

### :whale: Using Docker

    - Step 1: Create Image

        ```sh
        $ docker build -t <IMAGE_NAME> .
        ```

    - Step 2: Run Container and Access Container Shell

      **Not Persistent**
        ```sh
        $ docker run -it <IMAGEM_NAME> /bin/bash
        ```

      **Persistent**
        ```sh
        $ docker run -v <VOLUME_NAME>:/adgen -it <IMAGEM_NAME> /bin/bash
        ```
