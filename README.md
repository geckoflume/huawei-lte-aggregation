# huawei-lte-aggregation
OpenWrt package to enable and force Huawei B715s-23 LTE bands (and DL Carrier Aggregation (CA)).  
With no bands specified, uses specific bands: B28 UL and B28+B7+B3 DL (useful for french MNO Free Mobile).

Releases available here: https://github.com/geckoflume/huawei-lte-aggregation/releases

## Contents
```bash
📦huawei-lte-aggregation
 ┣ 📂src
 ┃ ┣ 📜Makefile
 ┃ ┣ 📜base64.c
 ┃ ┣ 📜base64.h
 ┃ ┣ 📜huawei-lte-aggregation.c
 ┃ ┣ 📜netutils.c
 ┃ ┣ 📜netutils.h
 ┃ ┣ 📜sha256.c
 ┃ ┗ 📜sha256.h
 ┣ 📜.gitignore
 ┣ 📜LICENSE
 ┣ 📜Makefile
 ┗ 📜README.md
 ```

 ## Requirements
- GNU toolchain: GCC, GNU make (optional, in case you want to run it on your machine)
- Basic understanding of cross compilation in order to build this package for OpenWrt (https://openwrt.org/docs/guide-developer/helloworld/start)

## How to build
In order to run the scripts, you have to install the requirements and compile huawei-lte-aggregation for your platform.

### Standard
1. Install the GNU toolchain for your distro, for Debian/Ubuntu
```bash
sudo apt install gcc-defaults
```

2. Compile
```bash
cd /path/to/huawei-lte-aggregation/src
make clean
make
```

### OpenWrt package
1. Download the OpenWrt SDK for your router platform here: https://downloads.openwrt.org/snapshots/targets/

2. Extract it using 
```bash
tar xz openwrt-sdk-<Platform>_gcc-<version>_musl.Linux-x86_64.tar.xz
```

3. Add a new feed to the SDK
```bash
mkdir -p mypackages/examples
cp -r /path/to/huawei-lte-aggregation mypackages/examples/
cd /path/to/openwrt-sdk-<Platform>_gcc-<version>_musl.Linux-x86_64
echo "src-link mypackages /path/to/mypackages" > feeds.conf
./scripts/feeds update mypackages
./scripts/feeds install -a -p mypackages
```

4. Compile for your platform
```bash
cd /path/to/openwrt-sdk-<Platform>_gcc-<version>_musl.Linux-x86_64
make package/huawei-lte-aggregation/{clean,compile}
```

Your package can be found in `/path/to/openwrt-sdk-<Platform>_gcc-<version>_musl.Linux-x86_64/bin/packages/<arch>/mypackages/huawei-lte-aggregation_0.1-1_<arch>.ipk`.

#### (Optional) How to deploy and install
```bash
scp huawei-lte-aggregation_0.1-1_<arch>.ipk root@ip:/tmp
ssh root@ip 'opkg install /tmp/huawei-lte-aggregation_0.1-1_<arch>.ipk'
```

#### (Optional) How to uninstall
```bash
scp huawei-lte-aggregation_0.1-1_<arch>.ipk root@ip:/tmp
ssh root@ip 'opkg remove huawei-lte-aggregation'
```

## How to use
```bash
huawei-lte-aggregation <huawei-ip> <password> [ul-band] [dl-band]
```

Example:
- To run with default bands (B28 UL and B28+B7+B3 DL)
```bash
huawei-lte-aggregation 192.168.8.1 pass
```
- To run with specific bands
```bash
huawei-lte-aggregation 192.168.8.1 pass 8000000 8000044
```

### Bands combinations
| Band | FDD/TDD | Frequency | Hex         |
|------|---------|-----------|-------------|
| B1   | FDD     | 2100      | 1           |
| B2   | FDD     | 1900      | 2           |
| B3   | FDD     | 1800      | 4           |
| B4   | FDD     | 1700      | 8           |
| B5   | FDD     | 850       | 10          |
| B6   | FDD     | 800       | 20          |
| B7   | FDD     | 2600      | 40          |
| B8   | FDD     | 900       | 80          |
| B19  | FDD     | 850       | 40000       |
| B20  | FDD     | 800       | 80000       |
| B26  | FDD     | 850       | 2000000     |
| B28  | SDL     | 700       | 8000000     |
| B32  | TDD     | 1500      | 80000000    |
| B38  | TDD     | 2600      | 2000000000  |
| B40  | TDD     | 2300      | 8000000000  |
| B41  | TDD     | 2500      | 10000000000 |

For example, B28+B7+B3 = 8000000+40+4 = 8000044

### Cron job
For best results, run this program with a Cron job (https://openwrt.org/docs/guide-user/base-system/cron).

Example, to run every day at 05:00
```bash
# Write out current crontab
crontab -l > mycron
# echo new cron into cron file
echo "0 5 * * * huawei-lte-aggregation 192.168.8.1 pwd 2>&1 | /usr/bin/logger -t huawei-lte-aggregation" >> mycron
# Install new cron file
crontab mycron
rm mycron
```