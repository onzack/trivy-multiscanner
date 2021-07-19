# Trivy multiscanner
Scan a list of container images using Aqua Security's trivy CLI tool. See: https://github.com/aquasecurity/trivy

# Quick guide
## Prerequisites
- Docker or an other supported container runtime
- trivy CLI, see: https://aquasecurity.github.io/trivy/v0.19.1/getting-started/installation/

## Installation
1. Clone this repository to your local machine.
2. Make the script executable: `chmod +x ./trivy-multiscanner/trivy-multiscanner.bash`
3. Create a file with a list of container images. Example: example-images-list.txt:  
   ```
   ubuntu:20.04
   quay.io/onzack/telegraf-swm:latest
   ```
4. Start the script and pass the path to the file with the list of container images:  
   ```
   ./trivy-multiscanner/trivy-multiscanner.bash ./trivy-multiscanner/example-images-list.txt
   ```

## Example output
```
  ______  __   _  _____      __     _____  _   __
 |  __  ||  \ | ||___  /    /  \   |  ___|| | / /
 | |  | || \ \| |   / /    / /\ \  | |    | |/ /
 | |__| || |\ | |  / /__  / ____ \ | |___ | |\ \
 |______||_| \__| /_____|/_/    \_\|_____||_| \_\

Welcome to ONZACK AG - www.onzack.com
This script scans a list of container images using Aqua Security's trivy CLI tool - https://github.com/aquasecurity/trivy

######## List of images to scan:
ubuntu:20.04
quay.io/onzack/telegraf-swm:latest

######## Image: ubuntu:20.04
----- Pull image -----
20.04: Pulling from library/ubuntu
a31c7b29f4ad: Pull complete 
Digest: sha256:b3e2e47d016c08b3396b5ebe06ab0b711c34e7f37b98c9d37abe794b71cea0a2
Status: Downloaded newer image for ubuntu:20.04
docker.io/library/ubuntu:20.04

----- Show age -----
Image: ubuntu:20.04 was created 5 days ago

----- Scan image -----
2021-07-19T19:11:45.217+0200	INFO	Detecting Ubuntu vulnerabilities...
2021-07-19T19:11:45.220+0200	INFO	Trivy skips scanning programming language libraries because no supported file was detected

ubuntu:20.04 (ubuntu 20.04)
===========================
Total: 27 (UNKNOWN: 0, LOW: 27, MEDIUM: 0, HIGH: 0, CRITICAL: 0)

+-------------+------------------+----------+------------------------+---------------+-----------------------------------------+
|   LIBRARY   | VULNERABILITY ID | SEVERITY |   INSTALLED VERSION    | FIXED VERSION |                  TITLE                  |
+-------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| bash        | CVE-2019-18276   | LOW      | 5.0-6ubuntu1.1         |               | bash: when effective UID is not         |
|             |                  |          |                        |               | equal to its real UID the...            |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-18276   |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| coreutils   | CVE-2016-2781    |          | 8.30-3ubuntu2          |               | coreutils: Non-privileged               |
|             |                  |          |                        |               | session can escape to the               |
|             |                  |          |                        |               | parent session in chroot                |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2016-2781    |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libc-bin    | CVE-2016-10228   |          | 2.31-0ubuntu9.2        |               | glibc: iconv program can hang           |
|             |                  |          |                        |               | when invoked with the -c option         |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2016-10228   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2019-25013   |          |                        |               | glibc: buffer over-read in              |
|             |                  |          |                        |               | iconv when processing invalid           |
|             |                  |          |                        |               | multi-byte input sequences in...        |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-25013   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-27618   |          |                        |               | glibc: iconv when processing            |
|             |                  |          |                        |               | invalid multi-byte input                |
|             |                  |          |                        |               | sequences fails to advance the...       |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-27618   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-29562   |          |                        |               | glibc: assertion failure in iconv       |
|             |                  |          |                        |               | when converting invalid UCS4            |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-29562   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-6096    |          |                        |               | glibc: signed comparison                |
|             |                  |          |                        |               | vulnerability in the                    |
|             |                  |          |                        |               | ARMv7 memcpy function                   |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-6096    |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2021-27645   |          |                        |               | glibc: Use-after-free in                |
|             |                  |          |                        |               | addgetnetgrentX function                |
|             |                  |          |                        |               | in netgroupcache.c                      |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-27645   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2021-3326    |          |                        |               | glibc: Assertion failure in             |
|             |                  |          |                        |               | ISO-2022-JP-3 gconv module              |
|             |                  |          |                        |               | related to combining characters         |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-3326    |
+-------------+------------------+          +                        +---------------+-----------------------------------------+
| libc6       | CVE-2016-10228   |          |                        |               | glibc: iconv program can hang           |
|             |                  |          |                        |               | when invoked with the -c option         |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2016-10228   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2019-25013   |          |                        |               | glibc: buffer over-read in              |
|             |                  |          |                        |               | iconv when processing invalid           |
|             |                  |          |                        |               | multi-byte input sequences in...        |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-25013   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-27618   |          |                        |               | glibc: iconv when processing            |
|             |                  |          |                        |               | invalid multi-byte input                |
|             |                  |          |                        |               | sequences fails to advance the...       |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-27618   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-29562   |          |                        |               | glibc: assertion failure in iconv       |
|             |                  |          |                        |               | when converting invalid UCS4            |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-29562   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-6096    |          |                        |               | glibc: signed comparison                |
|             |                  |          |                        |               | vulnerability in the                    |
|             |                  |          |                        |               | ARMv7 memcpy function                   |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-6096    |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2021-27645   |          |                        |               | glibc: Use-after-free in                |
|             |                  |          |                        |               | addgetnetgrentX function                |
|             |                  |          |                        |               | in netgroupcache.c                      |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-27645   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2021-3326    |          |                        |               | glibc: Assertion failure in             |
|             |                  |          |                        |               | ISO-2022-JP-3 gconv module              |
|             |                  |          |                        |               | related to combining characters         |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-3326    |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libgcrypt20 | CVE-2021-33560   |          | 1.8.5-5ubuntu1         |               | libgcrypt: mishandles ElGamal           |
|             |                  |          |                        |               | encryption because it lacks             |
|             |                  |          |                        |               | exponent blinding to address a...       |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-33560   |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libgnutls30 | CVE-2021-20231   |          | 3.6.13-2ubuntu1.3      |               | gnutls: Use after free in               |
|             |                  |          |                        |               | client key_share extension              |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-20231   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2021-20232   |          |                        |               | gnutls: Use after free                  |
|             |                  |          |                        |               | in client_send_params in                |
|             |                  |          |                        |               | lib/ext/pre_shared_key.c                |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-20232   |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libpcre3    | CVE-2017-11164   |          | 2:8.39-12build1        |               | pcre: OP_KETRMAX feature in the         |
|             |                  |          |                        |               | match function in pcre_exec.c           |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2017-11164   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2019-20838   |          |                        |               | pcre: buffer over-read in               |
|             |                  |          |                        |               | JIT when UTF is disabled                |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-20838   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-14155   |          |                        |               | pcre: integer overflow in libpcre       |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-14155   |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libsystemd0 | CVE-2020-13529   |          | 245.4-4ubuntu3.7       |               | systemd: DHCP FORCERENEW                |
|             |                  |          |                        |               | authentication not implemented          |
|             |                  |          |                        |               | can cause a system running the...       |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-13529   |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libtasn1-6  | CVE-2018-1000654 |          | 4.16.0-2               |               | libtasn1: Infinite loop in              |
|             |                  |          |                        |               | _asn1_expand_object_id(ptree)           |
|             |                  |          |                        |               | leads to memory exhaustion              |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-1000654 |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libudev1    | CVE-2020-13529   |          | 245.4-4ubuntu3.7       |               | systemd: DHCP FORCERENEW                |
|             |                  |          |                        |               | authentication not implemented          |
|             |                  |          |                        |               | can cause a system running the...       |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-13529   |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| login       | CVE-2013-4235    |          | 1:4.8.1-1ubuntu5.20.04 |               | shadow-utils: TOCTOU race               |
|             |                  |          |                        |               | conditions by copying and               |
|             |                  |          |                        |               | removing directory trees                |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2013-4235    |
+-------------+                  +          +                        +---------------+                                         +
| passwd      |                  |          |                        |               |                                         |
|             |                  |          |                        |               |                                         |
|             |                  |          |                        |               |                                         |
|             |                  |          |                        |               |                                         |
+-------------+------------------+----------+------------------------+---------------+-----------------------------------------+

######## Image: quay.io/onzack/telegraf-swm:latest
----- Pull image -----
latest: Pulling from onzack/telegraf-swm
c549ccf8d472: Pull complete 
918d78e87d43: Pull complete 
c3b3c2333fc1: Pull complete 
ead8b4f7177c: Pull complete 
Digest: sha256:c8fa16443300ba2e1df334b0fced2e745eeb4e18e16996af2e77d1a856a749c5
Status: Downloaded newer image for quay.io/onzack/telegraf-swm:latest
quay.io/onzack/telegraf-swm:latest

----- Show age -----
Image: quay.io/onzack/telegraf-swm:latest was created 12 days ago

----- Scan image -----
2021-07-19T19:11:58.246+0200	WARN	You should avoid using the :latest tag as it is cached. You need to specify '--clear-cache' option when :latest image is changed
2021-07-19T19:12:01.143+0200	INFO	Detecting Ubuntu vulnerabilities...
2021-07-19T19:12:01.184+0200	INFO	Trivy skips scanning programming language libraries because no supported file was detected

quay.io/onzack/telegraf-swm:latest (ubuntu 20.04)
=================================================
Total: 27 (UNKNOWN: 0, LOW: 27, MEDIUM: 0, HIGH: 0, CRITICAL: 0)

+-------------+------------------+----------+------------------------+---------------+-----------------------------------------+
|   LIBRARY   | VULNERABILITY ID | SEVERITY |   INSTALLED VERSION    | FIXED VERSION |                  TITLE                  |
+-------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| bash        | CVE-2019-18276   | LOW      | 5.0-6ubuntu1.1         |               | bash: when effective UID is not         |
|             |                  |          |                        |               | equal to its real UID the...            |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-18276   |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| coreutils   | CVE-2016-2781    |          | 8.30-3ubuntu2          |               | coreutils: Non-privileged               |
|             |                  |          |                        |               | session can escape to the               |
|             |                  |          |                        |               | parent session in chroot                |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2016-2781    |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libc-bin    | CVE-2016-10228   |          | 2.31-0ubuntu9.2        |               | glibc: iconv program can hang           |
|             |                  |          |                        |               | when invoked with the -c option         |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2016-10228   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2019-25013   |          |                        |               | glibc: buffer over-read in              |
|             |                  |          |                        |               | iconv when processing invalid           |
|             |                  |          |                        |               | multi-byte input sequences in...        |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-25013   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-27618   |          |                        |               | glibc: iconv when processing            |
|             |                  |          |                        |               | invalid multi-byte input                |
|             |                  |          |                        |               | sequences fails to advance the...       |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-27618   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-29562   |          |                        |               | glibc: assertion failure in iconv       |
|             |                  |          |                        |               | when converting invalid UCS4            |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-29562   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-6096    |          |                        |               | glibc: signed comparison                |
|             |                  |          |                        |               | vulnerability in the                    |
|             |                  |          |                        |               | ARMv7 memcpy function                   |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-6096    |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2021-27645   |          |                        |               | glibc: Use-after-free in                |
|             |                  |          |                        |               | addgetnetgrentX function                |
|             |                  |          |                        |               | in netgroupcache.c                      |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-27645   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2021-3326    |          |                        |               | glibc: Assertion failure in             |
|             |                  |          |                        |               | ISO-2022-JP-3 gconv module              |
|             |                  |          |                        |               | related to combining characters         |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-3326    |
+-------------+------------------+          +                        +---------------+-----------------------------------------+
| libc6       | CVE-2016-10228   |          |                        |               | glibc: iconv program can hang           |
|             |                  |          |                        |               | when invoked with the -c option         |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2016-10228   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2019-25013   |          |                        |               | glibc: buffer over-read in              |
|             |                  |          |                        |               | iconv when processing invalid           |
|             |                  |          |                        |               | multi-byte input sequences in...        |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-25013   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-27618   |          |                        |               | glibc: iconv when processing            |
|             |                  |          |                        |               | invalid multi-byte input                |
|             |                  |          |                        |               | sequences fails to advance the...       |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-27618   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-29562   |          |                        |               | glibc: assertion failure in iconv       |
|             |                  |          |                        |               | when converting invalid UCS4            |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-29562   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-6096    |          |                        |               | glibc: signed comparison                |
|             |                  |          |                        |               | vulnerability in the                    |
|             |                  |          |                        |               | ARMv7 memcpy function                   |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-6096    |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2021-27645   |          |                        |               | glibc: Use-after-free in                |
|             |                  |          |                        |               | addgetnetgrentX function                |
|             |                  |          |                        |               | in netgroupcache.c                      |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-27645   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2021-3326    |          |                        |               | glibc: Assertion failure in             |
|             |                  |          |                        |               | ISO-2022-JP-3 gconv module              |
|             |                  |          |                        |               | related to combining characters         |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-3326    |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libgcrypt20 | CVE-2021-33560   |          | 1.8.5-5ubuntu1         |               | libgcrypt: mishandles ElGamal           |
|             |                  |          |                        |               | encryption because it lacks             |
|             |                  |          |                        |               | exponent blinding to address a...       |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-33560   |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libgnutls30 | CVE-2021-20231   |          | 3.6.13-2ubuntu1.3      |               | gnutls: Use after free in               |
|             |                  |          |                        |               | client key_share extension              |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-20231   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2021-20232   |          |                        |               | gnutls: Use after free                  |
|             |                  |          |                        |               | in client_send_params in                |
|             |                  |          |                        |               | lib/ext/pre_shared_key.c                |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-20232   |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libpcre3    | CVE-2017-11164   |          | 2:8.39-12build1        |               | pcre: OP_KETRMAX feature in the         |
|             |                  |          |                        |               | match function in pcre_exec.c           |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2017-11164   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2019-20838   |          |                        |               | pcre: buffer over-read in               |
|             |                  |          |                        |               | JIT when UTF is disabled                |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-20838   |
+             +------------------+          +                        +---------------+-----------------------------------------+
|             | CVE-2020-14155   |          |                        |               | pcre: integer overflow in libpcre       |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-14155   |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libsystemd0 | CVE-2020-13529   |          | 245.4-4ubuntu3.7       |               | systemd: DHCP FORCERENEW                |
|             |                  |          |                        |               | authentication not implemented          |
|             |                  |          |                        |               | can cause a system running the...       |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-13529   |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libtasn1-6  | CVE-2018-1000654 |          | 4.16.0-2               |               | libtasn1: Infinite loop in              |
|             |                  |          |                        |               | _asn1_expand_object_id(ptree)           |
|             |                  |          |                        |               | leads to memory exhaustion              |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-1000654 |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libudev1    | CVE-2020-13529   |          | 245.4-4ubuntu3.7       |               | systemd: DHCP FORCERENEW                |
|             |                  |          |                        |               | authentication not implemented          |
|             |                  |          |                        |               | can cause a system running the...       |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-13529   |
+-------------+------------------+          +------------------------+---------------+-----------------------------------------+
| login       | CVE-2013-4235    |          | 1:4.8.1-1ubuntu5.20.04 |               | shadow-utils: TOCTOU race               |
|             |                  |          |                        |               | conditions by copying and               |
|             |                  |          |                        |               | removing directory trees                |
|             |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2013-4235    |
+-------------+                  +          +                        +---------------+                                         +
| passwd      |                  |          |                        |               |                                         |
|             |                  |          |                        |               |                                         |
|             |                  |          |                        |               |                                         |
|             |                  |          |                        |               |                                         |
+-------------+------------------+----------+------------------------+---------------+-----------------------------------------+
```

# Licence
Copyright 2021 ONZACK AG - www.onzack.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.