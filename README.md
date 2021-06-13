# Detached

Spawn detached processes in D.

**Note**: Phobos got this kind of functionality in version 2.076, so this library is no longer needed. Use [spawnProcess](http://dlang.org/phobos/std_process.html#.spawnProcess) with *Config.detached* flag instead. If *Config.detached* is available during the compilation this library fallbacks to the Phobos version.

[![Build Status](https://github.com/FreeSlave/detached/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/FreeSlave/detached/actions/workflows/ci.yml) [![Coverage Status](https://coveralls.io/repos/github/FreeSlave/detached/badge.svg?branch=master)](https://coveralls.io/github/FreeSlave/detached?branch=master)

Before version 2.076 standard D library did not provide a way to start detached process and required to [wait](http://dlang.org/phobos/std_process.html#.wait) on a returned Pid. 
Without waiting you would have got zombie processes (resource leakage) if parent process outlives its child.

**detached** solves this problem by introducing the *spawnProcessDetached* function 
which has almost the same API as [spawnProcess](http://dlang.org/phobos/std_process.html#.spawnProcess).

## Features

* Run process detached, i.e. with no need to *wait*.
* Actually reports errors from exec- functions unlike *spawnProcess* which just checks if executable and working directory exist before fork and hopes their states leave unchanged before exec. (Note: this is no longer the case. It was fixed in phobos 2.075)

## Missing features

* A way to close standard streams in spawned process (e.g. for daemon creation).

## Examples

### [Spawn](examples/spawn/source/app.d)

Simple program demonstrating the usage of spawnProcessDetached.

```
dub run :spawn  -- --workdir=/usr/local -- pwd
dub run :spawn  -- --stdout=/dev/null --stderr=/dev/null -- vlc
dub run :spawn -- -v HELLO=WORLD -- sh -c 'echo $HELLO'
```
