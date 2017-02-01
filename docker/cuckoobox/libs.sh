#!/usr/bin/env bash

# Collect cuckoo
echo "Cloning..."
mkdir -p libs/cuckoo
git clone https://github.com/cuckoosandbox/cuckoo.git libs/cuckoo/cuckoo
git clone https://github.com/cuckoosandbox/community.git libs/cuckoo/community
git clone https://github.com/cuckoosandbox/monitor.git libs/cuckoo/monitor

echo "Patching..."
# Hotpatch Cuckoo to give more better scores
find libs/cuckoo/community/modules -name allocates_rwx.py | xargs sed -ie 's/severity = [0-9.]*/severity = 0.01/'
find libs/cuckoo/community/modules -name creates_doc.py | xargs sed -ie 's/severity = [0-9.]*/severity = 0.01/'
find libs/cuckoo/community/modules -name raises_exception.py | xargs sed -ie 's/severity = [0-9.]*/severity = 0.01/'
find libs/cuckoo/community/modules -name recon_fingerprint.py | xargs sed -ie 's/severity = [0-9.]*/severity = 0.5/'
cp -r libs/cuckoo/community/* libs/cuckoo/cuckoo/

echo "Collecting pips..."
# Collect pip dependancies
mkdir -p libs/pipdeps
pip install -d libs/pipdeps -r pipfreeze.txt

echo "Collecting volatility..."
# These are the libraries that need to exist in the 'libs' folder within this directory
# volatility-2.4.1.tar.gz
mkdir -p libs/volatility
git clone https://github.com/volatilityfoundation/volatility.git libs/volatility
cd libs/volatility
git checkout 2.4.1
tar -zcf ../volatility-2.4.1.tar.gz *
