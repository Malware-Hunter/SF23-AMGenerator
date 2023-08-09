#!/bin/bash

pip install -r requirements.txt

python3 amgenerator.py --download -npd 2 -azk fa08a4ad8d8c9d3c56236d27bd9b99bb83c66c3fd65642d496ea2cbd13d4e8a4 --extraction --label -vtk d211226fd8cd68e10170dbc053a5cf6ca73d73ba51587eca4908c47046a57f18 --reanalyze-time 1 --file input/sha256_05.txt

