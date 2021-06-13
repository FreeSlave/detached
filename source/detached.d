/**
 * Spawn detached process.
 * Authors: 
 *  $(LINK2 https://github.com/FreeSlave, Roman Chistokhodov)
 *  
 * 
 *  Some parts are merely copied from $(LINK2 https://github.com/dlang/phobos/blob/master/std/process.d, std.process)
 * Copyright:
 *  Roman Chistokhodov, 2016
 * License: 
 *  $(LINK2 http://www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
 */

module detached;

version(Posix) private {
    import core.sys.posix.unistd;
    import core.sys.posix.fcntl;
    import core.stdc.errno;
    import std.typecons : tuple, Tuple;
}

version(Windows) private {
    import core.sys.windows.windows;
    import std.process : environment, escapeWindowsArgument;
}

import findexecutable;
static import std.stdio;

public import std.process : ProcessException, Config;
public import std.stdio : File, StdioException;

/**
 * Spawns a new process, optionally assigning it an arbitrary set of standard input, output, and error streams.
 * 
 * The function returns immediately, leaving the spawned process to execute in parallel with its parent. 
 * 
 * The spawned process is detached from its parent, so you should not wait on the returned pid.
 * 
 * Params:
 *  args = An array which contains the program name as the zeroth element and any command-line arguments in the following elements.
 *  stdin = The standard input stream of the spawned process.
 *  stdout = The standard output stream of the spawned process.
 *  stderr = The standard error stream of the spawned process.
 *  env = Additional environment variables for the child process.
 *  config = Flags that control process creation. Same as for spawnProcess.
 *  workingDirectory = The working directory for the new process.
 *  pid = Pointer to variable that will get pid value in case spawnProcessDetached succeed. Not used if null.
 * 
 * See_Also: $(LINK2 https://dlang.org/phobos/std_process.html#.spawnProcess, spawnProcess documentation)
 */
void spawnProcessDetached(in char[][] args, 
                          File stdin = std.stdio.stdin, 
                          File stdout = std.stdio.stdout, 
                          File stderr = std.stdio.stderr, 
                          const string[string] env = null, 
                          Config config = Config.none, 
                          in char[] workingDirectory = null, 
                          ulong* pid = null);

static if (!is(typeof({auto config = Config.detached;})))
{

version(Posix) private @nogc @trusted char* mallocToStringz(in char[] s) nothrow
{
    import core.stdc.string : strncpy;
    import core.stdc.stdlib : malloc;
    auto sz = cast(char*)malloc(s.length + 1);
    if (s !is null) {
        strncpy(sz, s.ptr, s.length);
    }
    sz[s.length] = '\0';
    return sz;
}

version(Posix) unittest
{
    import core.stdc.stdlib : free;
    import core.stdc.string : strcmp;
    auto s = mallocToStringz("string");
    assert(strcmp(s, "string") == 0);
    free(s);
    
    assert(strcmp(mallocToStringz(null), "") == 0);
}

version(Posix) private @nogc @trusted char** createExecArgv(in char[][] args, in char[] filePath) nothrow {
    import core.stdc.stdlib : malloc;
    auto argv = cast(char**)malloc((args.length+1)*(char*).sizeof);
    argv[0] = mallocToStringz(filePath);
    foreach(i; 1..args.length) {
        argv[i] = mallocToStringz(args[i]);
    }
    argv[args.length] = null;
    return argv;
}

version(Posix) unittest
{
    import core.stdc.string : strcmp;
    auto argv= createExecArgv(["program", "arg", "arg2"], "/absolute/path/program");
    assert(strcmp(argv[0], "/absolute/path/program") == 0);
    assert(strcmp(argv[1], "arg") == 0);
    assert(strcmp(argv[2], "arg2") == 0);
    assert(argv[3] is null);
}

version(Windows) private string escapeShellArguments(in char[][] args...) @trusted pure nothrow
{
    import std.exception : assumeUnique;
    char[] buf;

    @safe nothrow
    char[] allocator(size_t size)
    {
        if (buf.length == 0)
            return buf = new char[size];
        else
        {
            auto p = buf.length;
            buf.length = buf.length + 1 + size;
            buf[p++] = ' ';
            return buf[p..p+size];
        }
    }

    foreach (arg; args)
        escapeWindowsArgumentImpl!allocator(arg);
    return assumeUnique(buf);
}

version(Windows) private char[] escapeWindowsArgumentImpl(alias allocator)(in char[] arg)
    @safe nothrow
    if (is(typeof(allocator(size_t.init)[0] = char.init)))
{
    // References:
    // * http://msdn.microsoft.com/en-us/library/windows/desktop/bb776391(v=vs.85).aspx
    // * http://blogs.msdn.com/b/oldnewthing/archive/2010/09/17/10063629.aspx

    // Check if the string needs to be escaped,
    // and calculate the total string size.

    // Trailing backslashes must be escaped
    bool escaping = true;
    bool needEscape = false;
    // Result size = input size + 2 for surrounding quotes + 1 for the
    // backslash for each escaped character.
    size_t size = 1 + arg.length + 1;

    foreach_reverse (char c; arg)
    {
        if (c == '"')
        {
            needEscape = true;
            escaping = true;
            size++;
        }
        else
        if (c == '\\')
        {
            if (escaping)
                size++;
        }
        else
        {
            if (c == ' ' || c == '\t')
                needEscape = true;
            escaping = false;
        }
    }

    import std.ascii : isDigit;
    // Empty arguments need to be specified as ""
    if (!arg.length)
        needEscape = true;
    else
    // Arguments ending with digits need to be escaped,
    // to disambiguate with 1>file redirection syntax
    if (isDigit(arg[$-1]))
        needEscape = true;

    if (!needEscape)
        return allocator(arg.length)[] = arg;

    // Construct result string.

    auto buf = allocator(size);
    size_t p = size;
    buf[--p] = '"';
    escaping = true;
    foreach_reverse (char c; arg)
    {
        if (c == '"')
            escaping = true;
        else
        if (c != '\\')
            escaping = false;

        buf[--p] = c;
        if (escaping)
            buf[--p] = '\\';
    }
    buf[--p] = '"';
    assert(p == 0);

    return buf;
}

//from std.process
version(Posix) private void setCLOEXEC(int fd, bool on) nothrow @nogc
{
    import core.sys.posix.fcntl : fcntl, F_GETFD, FD_CLOEXEC, F_SETFD;
    auto flags = fcntl(fd, F_GETFD);
    if (flags >= 0)
    {
        if (on) flags |= FD_CLOEXEC;
        else    flags &= ~(cast(typeof(flags)) FD_CLOEXEC);
        flags = fcntl(fd, F_SETFD, flags);
    }
    assert (flags != -1 || .errno == EBADF);
}

//From std.process
version(Posix) private const(char*)* createEnv(const string[string] childEnv, bool mergeWithParentEnv)
{
    // Determine the number of strings in the parent's environment.
    int parentEnvLength = 0;
    if (mergeWithParentEnv)
    {
        if (childEnv.length == 0) return environ;
        while (environ[parentEnvLength] != null) ++parentEnvLength;
    }

    // Convert the "new" variables to C-style strings.
    auto envz = new const(char)*[parentEnvLength + childEnv.length + 1];
    int pos = 0;
    foreach (var, val; childEnv)
        envz[pos++] = (var~'='~val~'\0').ptr;

    // Add the parent's environment.
    foreach (environStr; environ[0 .. parentEnvLength])
    {
        int eqPos = 0;
        while (environStr[eqPos] != '=' && environStr[eqPos] != '\0') ++eqPos;
        if (environStr[eqPos] != '=') continue;
        auto var = environStr[0 .. eqPos];
        if (var in childEnv) continue;
        envz[pos++] = environStr;
    }
    envz[pos] = null;
    return envz.ptr;
}

//From std.process
version(Posix) @system unittest
{
    auto e1 = createEnv(null, false);
    assert (e1 != null && *e1 == null);

    auto e2 = createEnv(null, true);
    assert (e2 != null);
    int i = 0;
    for (; environ[i] != null; ++i)
    {
        assert (e2[i] != null);
        import core.stdc.string;
        assert (strcmp(e2[i], environ[i]) == 0);
    }
    assert (e2[i] == null);

    auto e3 = createEnv(["foo" : "bar", "hello" : "world"], false);
    assert (e3 != null && e3[0] != null && e3[1] != null && e3[2] == null);
    assert ((e3[0][0 .. 8] == "foo=bar\0" && e3[1][0 .. 12] == "hello=world\0")
         || (e3[0][0 .. 12] == "hello=world\0" && e3[1][0 .. 8] == "foo=bar\0"));
}

version (Windows) private LPVOID createEnv(const string[string] childEnv, bool mergeWithParentEnv)
{
    if (mergeWithParentEnv && childEnv.length == 0) return null;
    import std.array : appender;
    import std.uni : toUpper;
    auto envz = appender!(wchar[])();
    void put(string var, string val)
    {
        envz.put(var);
        envz.put('=');
        envz.put(val);
        envz.put(cast(wchar) '\0');
    }

    // Add the variables in childEnv, removing them from parentEnv
    // if they exist there too.
    auto parentEnv = mergeWithParentEnv ? environment.toAA() : null;
    foreach (k, v; childEnv)
    {
        auto uk = toUpper(k);
        put(uk, v);
        if (uk in parentEnv) parentEnv.remove(uk);
    }

    // Add remaining parent environment variables.
    foreach (k, v; parentEnv) put(k, v);

    // Two final zeros are needed in case there aren't any environment vars,
    // and the last one does no harm when there are.
    envz.put("\0\0"w);
    return envz.data.ptr;
}

version (Windows) @system unittest
{
    assert (createEnv(null, true) == null);
    assert ((cast(wchar*) createEnv(null, false))[0 .. 2] == "\0\0"w);
    auto e1 = (cast(wchar*) createEnv(["foo":"bar", "ab":"c"], false))[0 .. 14];
    assert (e1 == "FOO=bar\0AB=c\0\0"w || e1 == "AB=c\0FOO=bar\0\0"w);
}

private enum InternalError : ubyte
{
    noerror,
    doubleFork,
    exec,
    chdir,
    getrlimit,
    environment
}

version(Posix) private Tuple!(int, string) spawnProcessDetachedImpl(in char[][] args, 
                                                     ref File stdin, ref File stdout, ref File stderr, 
                                                     const string[string] env, 
                                                     Config config, 
                                                     in char[] workingDirectory, 
                                                     ulong* pid) nothrow
{
    import std.path : baseName;
    import std.string : toStringz;
    
    string filePath = args[0].idup;
    if (filePath.baseName == filePath) {
        auto candidate = findExecutable(filePath);
        if (!candidate.length) {
            return tuple(ENOENT, "Could not find executable: " ~ filePath);
        }
        filePath = candidate;
    }
    
    if (access(toStringz(filePath), X_OK) != 0) {
        return tuple(.errno, "Not an executable file: " ~ filePath);
    }
    
    static @trusted @nogc int safePipe(ref int[2] pipefds) nothrow
    {
        int result = pipe(pipefds);
        if (result != 0) {
            return result;
        }
        if (fcntl(pipefds[0], F_SETFD, FD_CLOEXEC) == -1 || fcntl(pipefds[1], F_SETFD, FD_CLOEXEC) == -1) {
            close(pipefds[0]);
            close(pipefds[1]);
            return -1;
        }
        return result;
    }
    
    int[2] execPipe, pidPipe;
    if (safePipe(execPipe) != 0) {
        return tuple(.errno, "Could not create pipe to check startup of child");
    }
    scope(exit) close(execPipe[0]);
    if (safePipe(pidPipe) != 0) {
        auto pipeError = .errno;
        close(execPipe[1]);
        return tuple(pipeError, "Could not create pipe to get pid of child");
    }
    scope(exit) close(pidPipe[0]);
    
    int getFD(ref File f) { 
        import core.stdc.stdio : fileno;
        return fileno(f.getFP()); 
    }
    
    int stdinFD, stdoutFD, stderrFD;
    try {
        stdinFD  = getFD(stdin);
        stdoutFD = getFD(stdout);
        stderrFD = getFD(stderr);
    } catch(Exception e) {
        return tuple(.errno ? .errno : EBADF, "Could not get file descriptors of standard streams");
    }
    
    static void abortOnError(int execPipeOut, InternalError errorType, int error) nothrow {
        error = error ? error : EINVAL;
        write(execPipeOut, &errorType, errorType.sizeof);
        write(execPipeOut, &error, error.sizeof);
        close(execPipeOut);
        _exit(1);
    }
    
    pid_t firstFork = fork();
    int lastError = .errno;
    if (firstFork == 0) {
        close(execPipe[0]);
        close(pidPipe[0]);
        
        int execPipeOut = execPipe[1];
        int pidPipeOut = pidPipe[1];
        
        pid_t secondFork = fork();
        if (secondFork == 0) {
            close(pidPipeOut);
        
            if (workingDirectory.length) {
                import core.stdc.stdlib : free;
                auto workDir = mallocToStringz(workingDirectory);
                if (chdir(workDir) == -1) {
                    free(workDir);
                    abortOnError(execPipeOut, InternalError.chdir, .errno);
                } else {
                    free(workDir);
                }
            }
            
            // ===== From std.process =====
            if (stderrFD == STDOUT_FILENO) {
                stderrFD = dup(stderrFD);
            }
            dup2(stdinFD,  STDIN_FILENO);
            dup2(stdoutFD, STDOUT_FILENO);
            dup2(stderrFD, STDERR_FILENO);

            setCLOEXEC(STDIN_FILENO, false);
            setCLOEXEC(STDOUT_FILENO, false);
            setCLOEXEC(STDERR_FILENO, false);
            
            if (!(config & Config.inheritFDs)) {
                import core.sys.posix.poll : pollfd, poll, POLLNVAL;
                import core.sys.posix.sys.resource : rlimit, getrlimit, RLIMIT_NOFILE;

                rlimit r;
                if (getrlimit(RLIMIT_NOFILE, &r) != 0) {
                    abortOnError(execPipeOut, InternalError.getrlimit, .errno);
                }
                immutable maxDescriptors = cast(int)r.rlim_cur;
                immutable maxToClose = maxDescriptors - 3;

                @nogc nothrow static bool pollClose(int maxToClose, int dontClose)
                {
                    import core.stdc.stdlib : malloc, free;

                    pollfd* pfds = cast(pollfd*)malloc(pollfd.sizeof * maxToClose);
                    scope(exit) free(pfds);
                    foreach (i; 0 .. maxToClose) {
                        pfds[i].fd = i + 3;
                        pfds[i].events = 0;
                        pfds[i].revents = 0;
                    }
                    if (poll(pfds, maxToClose, 0) >= 0) {
                        foreach (i; 0 .. maxToClose) {
                            if (pfds[i].fd != dontClose && !(pfds[i].revents & POLLNVAL)) {
                                close(pfds[i].fd);
                            }
                        }
                        return true;
                    }
                    else {
                        return false;
                    }
                }

                if (!pollClose(maxToClose, execPipeOut)) {
                    foreach (i; 3 .. maxDescriptors) {
                        if (i != execPipeOut) {
                            close(i);
                        }
                    }
                }
            } else {
                if (stdinFD  > STDERR_FILENO)  close(stdinFD);
                if (stdoutFD > STDERR_FILENO)  close(stdoutFD);
                if (stderrFD > STDERR_FILENO)  close(stderrFD);
            }
            // =====================
            
            const(char*)* envz;
            try {
                envz = createEnv(env, !(config & Config.newEnv));
            } catch(Exception e) {
                abortOnError(execPipeOut, InternalError.environment, EINVAL);
            }
            auto argv = createExecArgv(args, filePath);
            execve(argv[0], argv, envz);
            abortOnError(execPipeOut, InternalError.exec, .errno);
        }
        int forkErrno = .errno;
        
        write(pidPipeOut, &secondFork, pid_t.sizeof);
        close(pidPipeOut);
        
        if (secondFork == -1) {
            abortOnError(execPipeOut, InternalError.doubleFork, forkErrno);
        } else {
            close(execPipeOut);
            _exit(0);
        }
    }
    
    close(execPipe[1]);
    close(pidPipe[1]);
    
    if (firstFork == -1) {
        return tuple(lastError, "Could not fork");
    }
    
    InternalError status;
    auto readExecResult = read(execPipe[0], &status, status.sizeof);
    lastError = .errno;
    
    import core.sys.posix.sys.wait : waitpid;
    int waitResult;
    waitpid(firstFork, &waitResult, 0);
    
    if (readExecResult == -1) {
        return tuple(lastError, "Could not read from pipe to get child status");
    }
    
    try {
        if (!(config & Config.retainStdin ) && stdinFD  > STDERR_FILENO
                                        && stdinFD  != getFD(std.stdio.stdin ))
        stdin.close();
        if (!(config & Config.retainStdout) && stdoutFD > STDERR_FILENO
                                            && stdoutFD != getFD(std.stdio.stdout))
            stdout.close();
        if (!(config & Config.retainStderr) && stderrFD > STDERR_FILENO
                                            && stderrFD != getFD(std.stdio.stderr))
            stderr.close();
    } catch(Exception e) {
        
    }
    
    if (status == 0) {
        if (pid !is null) {
            pid_t actualPid = 0;
            if (read(pidPipe[0], &actualPid, pid_t.sizeof) >= 0) {
                *pid = actualPid;
            } else {
                *pid = 0;
            }
        }
        return tuple(0, "");
    } else {
        int error;
        readExecResult = read(execPipe[0], &error, error.sizeof);
        if (readExecResult == -1) {
            return tuple(.errno, "Error occured but could not read exec errno from pipe");
        }
        switch(status) {
            case InternalError.doubleFork: return tuple(error, "Could not fork twice");
            case InternalError.exec: return tuple(error, "Could not exec");
            case InternalError.chdir: return tuple(error, "Could not set working directory");
            case InternalError.getrlimit: return tuple(error, "getrlimit");
            case InternalError.environment: return tuple(error, "Could not set environment variables");
            default:return tuple(error, "Unknown error occured");
        }
    }
}

version(Windows) private void spawnProcessDetachedImpl(in char[] commandLine, 
                                                     ref File stdin, ref File stdout, ref File stderr, 
                                                     const string[string] env, 
                                                     Config config, 
                                                     in char[] workingDirectory, 
                                                     ulong* pid)
{
    import std.windows.syserror;
    
    // from std.process
    // Prepare environment.
    auto envz = createEnv(env, !(config & Config.newEnv));

    // Startup info for CreateProcessW().
    STARTUPINFO_W startinfo;
    startinfo.cb = startinfo.sizeof;
    static int getFD(ref File f) { return f.isOpen ? f.fileno : -1; }

    // Extract file descriptors and HANDLEs from the streams and make the
    // handles inheritable.
    static void prepareStream(ref File file, DWORD stdHandle, string which,
                              out int fileDescriptor, out HANDLE handle)
    {
        fileDescriptor = getFD(file);
        handle = null;
        if (fileDescriptor >= 0)
            handle = file.windowsHandle;
        // Windows GUI applications have a fd but not a valid Windows HANDLE.
        if (handle is null || handle == INVALID_HANDLE_VALUE)
            handle = GetStdHandle(stdHandle);

        DWORD dwFlags;
        if (GetHandleInformation(handle, &dwFlags))
        {
            if (!(dwFlags & HANDLE_FLAG_INHERIT))
            {
                if (!SetHandleInformation(handle,
                                          HANDLE_FLAG_INHERIT,
                                          HANDLE_FLAG_INHERIT))
                {
                    throw new StdioException(
                        "Failed to make "~which~" stream inheritable by child process ("
                        ~sysErrorString(GetLastError()) ~ ')',
                        0);
                }
            }
        }
    }
    int stdinFD = -1, stdoutFD = -1, stderrFD = -1;
    prepareStream(stdin,  STD_INPUT_HANDLE,  "stdin" , stdinFD,  startinfo.hStdInput );
    prepareStream(stdout, STD_OUTPUT_HANDLE, "stdout", stdoutFD, startinfo.hStdOutput);
    prepareStream(stderr, STD_ERROR_HANDLE,  "stderr", stderrFD, startinfo.hStdError );

    if ((startinfo.hStdInput  != null && startinfo.hStdInput  != INVALID_HANDLE_VALUE)
     || (startinfo.hStdOutput != null && startinfo.hStdOutput != INVALID_HANDLE_VALUE)
     || (startinfo.hStdError  != null && startinfo.hStdError  != INVALID_HANDLE_VALUE))
        startinfo.dwFlags = STARTF_USESTDHANDLES;

    // Create process.
    PROCESS_INFORMATION pi;
    DWORD dwCreationFlags =
        CREATE_UNICODE_ENVIRONMENT |
        ((config & Config.suppressConsole) ? CREATE_NO_WINDOW : 0);
        
        
    import std.utf : toUTF16z, toUTF16;
    auto pworkDir = workingDirectory.toUTF16z();
    if (!CreateProcessW(null, (commandLine ~ "\0").toUTF16.dup.ptr, null, null, true, dwCreationFlags,
                        envz, workingDirectory.length ? pworkDir : null, &startinfo, &pi))
        throw ProcessException.newFromLastError("Failed to spawn new process");

    enum STDERR_FILENO = 2;
    // figure out if we should close any of the streams
    if (!(config & Config.retainStdin ) && stdinFD  > STDERR_FILENO
                                        && stdinFD  != getFD(std.stdio.stdin ))
        stdin.close();
    if (!(config & Config.retainStdout) && stdoutFD > STDERR_FILENO
                                        && stdoutFD != getFD(std.stdio.stdout))
        stdout.close();
    if (!(config & Config.retainStderr) && stderrFD > STDERR_FILENO
                                        && stderrFD != getFD(std.stdio.stderr))
        stderr.close();

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (pid) {
        *pid = pi.dwProcessId;
    }
}

void spawnProcessDetached(in char[][] args, 
                          File stdin = std.stdio.stdin, 
                          File stdout = std.stdio.stdout, 
                          File stderr = std.stdio.stderr, 
                          const string[string] env = null, 
                          Config config = Config.none, 
                          in char[] workingDirectory = null, 
                          ulong* pid = null)
{
    import core.exception : RangeError;
    
    version(Posix) {
        if (args.length == 0) throw new RangeError();
        auto result = spawnProcessDetachedImpl(args, stdin, stdout, stderr, env, config, workingDirectory, pid);
        if (result[0] != 0) {
            .errno = result[0];
            throw ProcessException.newFromErrno(result[1]);
        }
    } else version(Windows) {
        auto commandLine = escapeShellArguments(args);
        if (commandLine.length == 0) throw new RangeError("Command line is empty");
        spawnProcessDetachedImpl(commandLine, stdin, stdout, stderr, env, config, workingDirectory, pid);
    }
}

}
else
{
    import std.process : spawnProcess;
    void spawnProcessDetached(in char[][] args, 
                          File stdin = std.stdio.stdin, 
                          File stdout = std.stdio.stdout, 
                          File stderr = std.stdio.stderr, 
                          const string[string] env = null, 
                          Config config = Config.none, 
                          in char[] workingDirectory = null, 
                          ulong* pid = null)
    {
        auto p = spawnProcess(args, stdin, stdout, stderr, env, config | Config.detached, workingDirectory);
        if (pid) {
            *pid = cast(typeof(*pid))p.processID;
        }
    }
}
///
unittest
{
    import std.exception : assertThrown;
    version(Posix) {
        try {
            auto devNull = File("/dev/null", "rwb");
            ulong pid;
            spawnProcessDetached(["whoami"], devNull, devNull, devNull, null, Config.none, "./test", &pid);
            assert(pid != 0);
            
            assertThrown(spawnProcessDetached(["./test/nonexistent"]));
            assertThrown(spawnProcessDetached(["./test/executable.sh"], devNull, devNull, devNull, null, Config.none, "./test/nonexistent"));
            assertThrown(spawnProcessDetached(["./dub.json"]));
            assertThrown(spawnProcessDetached(["./test/notreallyexecutable"]));
        } catch(Exception e) {
            
        }
    }
    version(Windows) {
        try {
            ulong pid;
            spawnProcessDetached(["whoami"], std.stdio.stdin, std.stdio.stdout, std.stdio.stderr, null, Config.none, "./test", &pid);
            
            assertThrown(spawnProcessDetached(["dub.json"]));
        } catch(Exception e) {
            
        }
    }
}

///ditto
void spawnProcessDetached(in char[][] args, const string[string] env, Config config = Config.none, in char[] workingDirectory = null, ulong* pid = null)
{
    spawnProcessDetached(args, std.stdio.stdin, std.stdio.stdout, std.stdio.stderr, env, config, workingDirectory, pid);
}
