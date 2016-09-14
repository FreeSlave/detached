import std.stdio;
import std.getopt;
import std.format;
import std.algorithm;

import detached;

int main(string[] args) {
    string workingDirectory;
    string stdinFileName = "-";
    string stdoutFileName = "-";
    string stderrFileName = "-";
    string[] envir;
    
    auto helpInformation = getopt(args, 
                                  "w|workdir", "Working directory of spawned process", &workingDirectory,
                                  "i|stdin", "File to use as standard input", &stdinFileName,
                                  "o|stdout", "File to use as standard output", &stdoutFileName,
                                  "e|stderr", "File to use as standard error", &stderrFileName,
                                  "v", "Set environment variable. Should be in from var=value", &envir
                                 );
    if (helpInformation.helpWanted)
    {
        defaultGetoptPrinter(format("Spawn detached process\nUsage: %s <program> [arguments...]", args[0]), helpInformation.options);
        return 0;
    }
    
    if (args.length == 1) {
        stderr.writeln("Expected program name");
        return 1;
    }
    
    string[string] envvars = null;
    foreach(v; envir) {
        auto var = findSplit(v, "=");
        envvars[var[0]] = var[2];
    }
    
    try {
        File stdinFile = stdinFileName == "-" ? stdin : File(stdinFileName, "rb");
        File stdoutFile = stdoutFileName == "-" ? stdout : File(stdoutFileName, "wb");
        File stderrFile = stderrFileName == "-" ? stderr : File(stderrFileName, "wb");
        
        ulong pid;
        spawnProcessDetached(args[1..$], stdinFile, stdoutFile, stderrFile, envvars, Config.none, workingDirectory, &pid);
        writeln("Pid: ", pid);
        return 0;
    } catch(ProcessException e) {
        stderr.writeln(e.msg);
        return 1;
    }
}