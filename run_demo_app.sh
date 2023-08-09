#!/bin/bash

printline() {
	echo "==========================================================="
}

printline
echo -n "Checking Python 3.8.10 ... "

VERSION=$(python3 -V | awk '{print $2}')
if [ "$VERSION" != "3.8.10" ]
then
	echo "ERROR."
	echo "    (1) You need Python 3.8.10 to run AMGenerator!"
	echo "    (2) Please, install Python 3.8.10 or use the Docker demo (run_demo_docker.sh)."
	printline
	exit
fi

echo "done."
printline

printline
echo -n "Installing Python requirements ... "

pip install -r requirements.txt  > /dev/null 2>&1

echo "done."
printline

echo ""

printline
echo "Running amgenerator.py ... "
echo ""

python3 amgenerator.py --download -npd 2 -azk fa08a4ad8d8c9d3c56236d27bd9b99bb83c66c3fd65642d496ea2cbd13d4e8a4 --extraction --label -vtk d211226fd8cd68e10170dbc053a5cf6ca73d73ba51587eca4908c47046a57f18 --reanalyze-time 1 --file input/sha256_05.txt

echo ""
echo "done."
printline
