# Detached

Spawn detached process in D.

Standard D library does not provide a way to start detached process and requires to [wait](http://dlang.org/phobos/std_process.html#.wait) on returned Pid. 
Without waiting you will get zombie processes (resource leakage) if parent process outlives its child.

**detached** solves this problem by introducing the *spawnProcessDetached* function 
which has almost the same API as [spawnProcess](http://dlang.org/phobos/std_process.html#.spawnProcess).

## Features

* Run process detached, i.e. with no need to *wait*.
* Actually reports errors from exec- functions unlike *spawnProcess* which just checks if executable and working directory exist before fork and hopes their states leave unchanged before exec.

## Missing features

* Windows support (will be later)
* A way to close standard streams in spawned process (e.g. for daemon creation).

## Examples

### [Spawn](examples/spawn/source/app.d)

Simple program demonstrating the usage of spawnProcessDetached.

```
dub run :spawn  -- --workdir=/usr/local -- pwd
dub run :spawn  -- --stdout=/dev/null --stderr=/dev/null -- vlc
dub run :spawn -- -v HELLO=WORLD -- sh -c 'echo $HELLO'
```
