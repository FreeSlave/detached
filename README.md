# Detached

Spawn detached processes in D.

[![Build Status](https://travis-ci.org/FreeSlave/detached.svg?branch=master)](https://travis-ci.org/FreeSlave/detached) [![Windows Build Status](https://ci.appveyor.com/api/projects/status/github/FreeSlave/detached?branch=master&svg=true)](https://ci.appveyor.com/project/FreeSlave/detached) [![Coverage Status](https://coveralls.io/repos/github/FreeSlave/detached/badge.svg?branch=master)](https://coveralls.io/github/FreeSlave/detached?branch=master)

Standard D library does not provide a way to start detached process and requires to [wait](http://dlang.org/phobos/std_process.html#.wait) on returned Pid. 
Without waiting you will get zombie processes (resource leakage) if parent process outlives its child.

**detached** solves this problem by introducing the *spawnProcessDetached* function 
which has almost the same API as [spawnProcess](http://dlang.org/phobos/std_process.html#.spawnProcess).

## Features

* Run process detached, i.e. with no need to *wait*.
* Actually reports errors from exec- functions unlike *spawnProcess* which just checks if executable and working directory exist before fork and hopes their states leave unchanged before exec.

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
