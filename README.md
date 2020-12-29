# huawei-lte-aggregation
OpenWrt package to enable and force Huawei B715s-23 LTE Carrier Aggregation (CA) on specific bands: B28 UL and B28+B7+B3 DL (useful for french MNO Free Mobile).

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
- GCC, GNU make (optional, in case you want to run it on your machine)
- Basic understanding of cross compilation in order to build this package for OpenWrt (https://openwrt.org/docs/guide-developer/helloworld/start)

## How to build
In order to run the scripts, you have to install the requirements and compile huawei-lte-aggregation for your platform.

1. Download the OpenWrt SDK for your router platform here: https://downloads.openwrt.org/snapshots/targets/

2. Extract it using 
```bash
tar xz openwrt-sdk-<Platform>_gcc-<version>_musl.Linux-x86_64.tar.xz
```

3. Add a new feed to the SDK
```bash
mkdir -p mypackages/examples
cp -r /path/to/this/repo mypackages/examples/
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

### (Optional) How to deploy and install
```bash
scp huawei-lte-aggregation_0.1-1_<arch>.ipk root@ip:/tmp
ssh root@ip 'opkg install /tmp/huawei-lte-aggregation_0.1-1_<arch>.ipk'
```

### (Optional) How to install
```bash
scp huawei-lte-aggregation_0.1-1_<arch>.ipk root@ip:/tmp
ssh root@ip 'opkg remove huawei-lte-aggregation'
```

## How to use
```bash
huawei-lte-aggregation <huawei-ip> <password>
```

For best results, run this program with a cron job.