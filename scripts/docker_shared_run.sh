#!/bin/bash

sudo docker run -v $(readlink -f .):/AMGenerator -it sf23/amgenerator bash scripts/run_app_in_docker.sh
