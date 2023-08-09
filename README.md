# AMGenerator

[AMGenerator Overview](https://github.com/Malware-Hunter/SF23-AMGenerator/blob/main/OVERVIEW.md)


## Clonning the GitHub repository

```bash

git clone https://github.com/Malware-Hunter/SF23-AMGenerator.git

cd SF23-AMGenerator

```

## Running **demo** scripts
  


**Option 1**: will install requirements in your Linux system and run amgenerator.py app
```bash
./run_demo_app.sh

```

**Option 2**: will download and execute the Docker image **sf23/amgenerator:latest** from [hub.docker.com](hub.docker.com)
```bash
./run_demo_docker.sh

```

**Option 3**: will download and execute the Docker image **sf23/amgenerator:latest** from [hub.docker.com](hub.docker.com) and initiave a container in **persistent** (shared) mode
```bash
./scripts/docker_shared_run.sh

```
**Datasets will be generated in the directory called outputs**
  

## Building and running your own Docker :whale: image


Installing Docker and building your image
```bash

sudo apt install docker docker.io

docker  build  -t  sf23/amgenerator:latest  .

```

Starting a Docker container

**Non persistent mode**: output files will be deleted when the container finished execution.
```bash

docker  run  -it  sf23/amgenerator

```
**Persistent mode**: output files will be saved and avaliable at the current directory.
```bash

docker run -v $(readlink -f .):/AMGenerator -it sf23/amgenerator bash scripts/run_app_in_docker.sh

ls outputs*

```

  
## :memo: Running AMGenerator in your Linux

Installing requirements
~~~sh
pip install -r requirements.txt
~~~

Running the app (make sure you have Python 3.8.10 in your system)
~~~sh
python3 amgenerator.py --download -npd 2 -azk fa08a4ad8d8c9d3c56236d27bd9b99bb83c66c3fd65642d496ea2cbd13d4e8a4 --extraction --label -vtk d211226fd8cd68e10170dbc053a5cf6ca73d73ba51587eca4908c47046a57f18 --reanalyze-time 1 --file input/sha256_05.txt
~~~

## :pushpin: Available Arguments:

```
usage: amgenerator.py [-h] --file FILE [--download] [--download_dir PATH]
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
                        Time to Wait for Reanalysis (in Minutes)
  --output-data PATH    Data Output Directory
```


  - **Not Persistent**

  ```sh
    $ docker run -it <IMAGEM_NAME> /bin/bash
  ```

  - **Persistent**

  ```sh
    $ docker run -v <VOLUME_NAME>:/amgen -it <IMAGEM_NAME> /bin/bash
  ```

* **Step 3:** Run Tool Command Line

## :keyboard: Usage Examples (Command Line)

* **download** APKs in **input/sha256_10.txt** with **3** parallel downloads
```sh
  $ python3 amgenerator.py --download -npd 3 -azk [AZ_KEY] --file input/sha256_10.txt
```

* **download** and **extract** APKs in **input/sha256_10.txt** with **10** parallel downloads and **5** parallel extractions
```sh
  $ python3 amgenerator.py --download -npd 10 -azk [AZ_KEY] --extraction -npe 5 --file input/sha256_20.txt
```

* **download**, **extract** and **label** APKs in **input/sha256_05.txt** with **2** parallel downloads
```sh
  $ python3 amgenerator.py --download -npd 2 -azk [AZ_KEY] --extraction --label -vtk [VT_KEY] --file input/sha256_05.txt
```

* **label** APKs in **input/sha256_20.txt** waiting **1** hour for reanalysis
```sh
  $ python3 amgenerator.py --label -vtk [VT_KEY] --reanalyze-time 1 --file input/sha256_20.txt
```
## :gear: Environments

AMGenerator has been tested in the following environments:

**Ubuntu 20.04**

- Kernel = `Linux version 5.4.0-120-generic (buildd@lcy02-amd64-006) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #136-Ubuntu SMP Fri Jun 10 13:40:48 UTC 2022`
- Python = `Python 3.8.10`


**Debian Buster (Docker container)**

- Kernel = `5.19.0-46-generic #47~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 21 15:35:31 UTC 2 x86_64 GNU/Linux`
- Python = `Python 3.8.10`


