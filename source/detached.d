
module detached;

version(Posix) private {
    import core.sys.posix.unistd;
    import core.sys.posix.fcntl;
    import core.stdc.errno;
    
    static import std.stdio;
    import std.typecons : tuple, Tuple;
    import std.process : environ;
    
    import findexecutable;
}

public import std.process : ProcessException, Config;
public import std.stdio : File;

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

version(Posix) private @trusted void ignorePipeErrors() nothrow
{
    import core.sys.posix.signal;
    import core.stdc.string : memset;
    
    sigaction_t ignoreAction;
    memset(&ignoreAction, 0, sigaction_t.sizeof);
    ignoreAction.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &ignoreAction, null);
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
        close(execPipe[1]);
        return tuple(.errno, "Could not create pipe to get pid of child");
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
        
        ignorePipeErrors();
        setsid();
        
        int execPipeOut = execPipe[1];
        int pidPipeOut = pidPipe[1];
        
        pid_t secondFork = fork();
        if (secondFork == 0) {
            close(pidPipeOut);
            ignorePipeErrors();
        
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
                    import core.stdc.stdlib : alloca;

                    pollfd* pfds = cast(pollfd*)alloca(pollfd.sizeof * maxToClose);
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
        
        write(pidPipeOut, &secondFork, pid_t.sizeof);
        close(pidPipeOut);
        
        if (secondFork == -1) {
            abortOnError(execPipeOut, InternalError.doubleFork, .errno);
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

version(Posix) private string makeErrorMessage(string msg, int error) {
    import core.stdc.string : strlen, strerror;
    import std.format : format;
    
    version (CRuntime_Glibc)
    {
        import core.stdc.string : strerror_r;
        char[1024] buf;
        auto errnoMsg = strerror_r(error, buf.ptr, buf.length);
    }
    else
    {
        import core.stdc.string : strerror;
        auto errnoMsg = strerror(error);
    }
    return format("%s: %s", msg, errnoMsg[0..strlen(errnoMsg)]);
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
    if (args.length == 0) throw new RangeError();
    auto result = spawnProcessDetachedImpl(args, stdin, stdout, stderr, env, config, workingDirectory, pid);
    if (result[0] != 0) {
        throw new ProcessException(makeErrorMessage(result[1], result[0]));
    }
}

void spawnProcessDetached(in char[][] args, const string[string] env, Config config = Config.none, in char[] workingDirectory = null, ulong* pid = null)
{
    spawnProcessDetached(args, std.stdio.stdin, std.stdio.stdout, std.stdio.stderr, env, config, workingDirectory, pid);
}
