import std.stdio;
import std.getopt;

import detached;

int main(string[] args) {
    string workingDirectory;
    string stdinFileName = "-";
    string stdoutFileName = "-";
    string stderrFileName = "-";
    
    
    auto helpInformation = getopt(args, 
                                  "w|workdir", "Working directory of spawned process", &workingDirectory,
                                  "i|stdin", "File to use as standard input", &stdinFileName,
                                  "o|stdout", "File to use as standard output", &stdoutFileName,
                                  "e|stderr", "File to use as standard error", &stderrFileName
                                 );
    if (helpInformation.helpWanted)
    {
        defaultGetoptPrinter("Spawn detached process.", helpInformation.options);
        return 0;
    }
    
    try {
        File stdinFile = stdinFileName == "-" ? stdin : File(stdinFileName, "rb");
        File stdoutFile = stdoutFileName == "-" ? stdout : File(stdoutFileName, "wb");
        File stderrFile = stderrFileName == "-" ? stderr : File(stderrFileName, "wb");
        
        ulong pid;
        spawnProcessDetached(args[1..$], stdinFile, stdoutFile, stderrFile, null, Config.none, workingDirectory, &pid);
        writeln("Pid: ", pid);
        return 0;
    } catch(ProcessException e) {
        stderr.writeln(e.msg);
        return 1;
    }
}