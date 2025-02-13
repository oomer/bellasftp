# bellasftp
A libssh based sftp server with integrated Bella render engine

Tested on Ubuntu 22.04 LTS

**get code**
```sh
git clone https://github.com/oomer/bellasftp.git
```

**build libssh**
```sh
apt install -y cmake libsodium-dev zlib1g-dev libssl-dev libcurl4-openssl-dev
curl -O https://www.libssh.org/files/0.11/libssh-0.11.1.tar.xz
tar -xvf libssh-0.11.1.tar.xz
cd libssh-0.11.1
mkdir build
cd build
cmake ..
make
make install
```

**bella_engine_sdk**
```sh
apt install -y build-essential curl libx11-dev libgl1-mesa-dev
curl -O https://downloads.bellarender.com/bella_engine_sdk-24.6.0.tar.gz
tar -xvf bella_engine_sdk-24.6.0.tar.gz -C bellasftp --strip-components=1
cd bella_engine_sdk
sed -i 's/^\(\s*\)\(-Werror\)/\1#\2/' makefile
```

**build bellasftp**
```sh
ssh-keygen -t rsa -f server_key -N ""

```