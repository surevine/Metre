Building Metre
=======

Cooking time
----

Approximately one minute.

Ingredients
----

* git
* CMake 2.8 (or so)
* libicu

Source control is within Git (github is the public one). The software is built using CMake
for production builds - there's a Makefile as well which will
configure and build all the dependencies for you.

libunbound provides async DNS, including DNSSEC, and libevent provides buffered async
I/O, which should work well both on Linux and Windows.

Finally OpenSSL supplies crypto, X.509 primitives, and TLS. This was chosen mostly due
to OpenSSL having a FIPS certificate.

An Ubuntu/Debian APT line reads like:

```sh
apt-get install git build-essential clang cmake libc++-dev libc++abi-dev libicu-dev libexpat-dev
```

A CentOS yum line might instead read:

```sh
yum install git build-essential gcc gcc-c++ libicu-devel autoconf libtool valgrind make wget tar rpm-build redhat-lsb-core expat-devel bind-utils
```

... though for CentOS you'll also need devtoolset-2 and a manually compiled CMake.

Method
----

First, clone the source. You can access this anonymously via HTTPS:

```sh
git clone --recursive https://github.com/dwd/metre
```

Enter the directory:

```sh
cd metre
```

### Docker

Because this uses a multi-stage build, there are no dependencies other than Docker, so
the following command is all that is required:

```
docker build -t surevinecom/metre .
```

### UNIX

A simple `make` will do the following for you - but if you're developing, you'll just need the final stage.

Now initialize and clone the submodules, and setup dependencies:

```sh
make pre-build
```

*Optionally* you can generate new DH parameter files,
replacing those within the `./gen` directory. DH parameters are not private, but using
the same ones as everyone else might mean that weaker ones, at least, could be cracked. Or maybe we've created weak ones. Either way, should you want to, this will take about 10 minutes on a fast machine:

```sh
rm gen/dh*
make dhparams
```

Metre may, in the future, generate the shorter keys on boot to improve their security.
to replace those within the `./gen` directory. DH parameters are not private, but using
the same ones as everyone else might mean that weaker ones, at least, could be cracked.

Metre may, in the future, generate the shorter keys on boot to improve their security.
Create a build directory and change to it. I usually use something like "build" within the
source directory, but you can do anything you like, really. The instructions will assume
you do **EXACTLY AS I SAY** however:

```sh
mkdir -p build
cd build
```

Now let cmake do its magic:

```sh
cmake ..
```

And then, finally, you can just build - the build is very parallel, so use all your cores. I
have 12. Go me:

```sh
make -j12
```

You'll now have the executable built as `./build/metre`, relative to the source tree. You'll
want to look at the bad example config file at `./metre.conf.xml` and you'll need a DNSSEC
keys file, which you could make *insecurely* by `dig . DNSSEC > ./keys`. 

### Windows

First, build OpenSSL. You'll need Perl for this (and optionally nasm; the instructions here are without):

```sh
cd deps\openssl
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64"
perl Configure no-asm no-shared VC-WIN64A
nmake clean
nmake
cd ..\..
```

Next, create a build dir:

```sh
mkdir build
cd build
```

Do the CMake thing - note the odd incantations:

```sh
cmake .. -G "Visual Studio 15 2017 Win64" -Dgtest_force_shared_crt:BOOL=true
cmake --build .
```

You should now have Metre in build\Debug\metre.exe and the test suite in build\Debug\metre-test.exe

Fun, eh?

Serves
----

Around 100k domains, I suspect.
