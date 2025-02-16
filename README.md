# bellasftp
A prototype of a libssh based sftp server with integrated Bella render engine

> [!WARNING]
> This is a prototype and not intended for production use.
> It is not secure and should not be used in a production environment.
> It is only intended to be used for development purposes.
> Tested on a Ubuntu 22.04 server and MacOS client.

## Features

- user/password for authentication
- upload .bsz file
- download .png file
- monitors render progress
- [TODO] curl support for uploading and downloading files

## Usage

 Launch a sftp server on port 2225 on the server side:
```sh
bellasftp
```

On the client side: (password is "render")
```
sftp -P 2225 bella@server_ip
```

upload .bsz file
```
put orange-juice.bsz
```

start render ( sftp command override to start render, SFTP protocol has a SSH_FXP_EXTENSION but this requires client to support these features.)
```
mkdir render
```

monitor ( hijacked sftp command to monitor progress, SFTP protocoal has no mechanism for passing arbitrary text )
```
cd progress
```

download .png file ( server side name is hardcoded as oomer.png )
( client side name can be different )
```
get orange-juice.png
```


## Build


**get code**
```sh
git clone https://github.com/oomer/bellasftp.git
```

**build libssh**
```sh
apt install -y build-essential curl 
apt install -y cmake libsodium-dev zlib1g-dev libssl-dev
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
cd ../..
apt install -y libx11-dev libgl1-mesa-dev
curl -O https://downloads.bellarender.com/bella_engine_sdk-24.6.0.tar.gz
tar -xvf bella_engine_sdk-24.6.0.tar.gz -C bellasftp --strip-components=1
cd bellasftp
sed -i 's/^OUTNAME\s*=.*/OUTNAME         =bellasftp/' makefile
sed -i '/^[ \t]*-Werror/d' makefile
sed -i '/^\s*-lvulkan/i\\-lssh\\\n-lcurl\\' makefile
sed -i 's/^OBJS\s*=.*/OBJS = bellasftp.o/' makefile
```

**build bellasftp**
```sh
apt install -y libcurl4-openssl-dev
ssh-keygen -t rsa -f server_key -N ""
make
```

**run**
```sh
bin/Linux/bellasftp
```