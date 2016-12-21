# Collect cuckoo
mkdir -p libs/cuckoo
git clone https://github.com/cuckoosandbox/cuckoo.git libs/cuckoo/cuckoo
git clone https://github.com/cuckoosandbox/community.git libs/cuckoo/community
git clone https://github.com/cuckoosandbox/monitor.git libs/cuckoo/monitor
cp -r libs/cuckoo/community/* libs/cuckoo/cuckoo/

# libraries needed to download ssdeep
sudo apt-get install python-dev libffi-dev libfuzzy-dev

# Collect pip dependancies
mkdir -p libs/pipdeps
pip download -d libs/pipdeps -r pipfreeze.txt

# These are the libraries that need to exist in the 'libs' folder within this directory
# volatility-2.4.1.tar.gz
mkdir -p libs/volatility
git clone https://github.com/volatilityfoundation/volatility.git libs/volatility
cd libs/volatility
git checkout 2.4.1
tar -zcf ../volatility-2.4.1.tar.gz *
