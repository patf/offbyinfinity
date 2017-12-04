---
title: "Sandboxing ImageMagick with nsjail"
date: 2017-12-04T01:08:52+01:00
draft: false
---

ImageMagick is the go-to image conversion library in many environments. It's
written in C and [doesn't have the best track record on security](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=imagemagick).
Last year, a major vulnerability called [ImageTragick](https://imagetragick.com/)
(yes, there's a logo) made the news. [Even Facebook turned out to be vulnerable.](http://4lemon.ru/2017-01-17_facebook_imagetragick_remote_code_execution.html)

While [secure alternatives exist](https://www.imageflow.io/),
many existing projects have a hard dependency on ImageMagick and abstracting
the image conversion can be quite involved. If you find yourself in a situation
where you can't avoid using ImageMagick, sandboxing can help you mitigate the
damage in the event of a compromise.

## Enter nsjail

[nsjail](http://nsjail.com/), written by Google, calls itself "a light-weight
process isolation tool." It uses a number of Linux kernel features that allow
users to isolate processes in dedicated namespaces, limit file system access,
put constraints on their resource usage and to filter syscalls.

My goals for this sandbox can be broken down like this:

- No network access — all images are local, so there's no reason for ImageMagick
  to talk to anyone over the network
- Read-only access to the binaries, library and configuration files and write
  access to the folder in which images live temporarily during conversion
- Sane maximum execution times — somewhat limiting the impact of DoS attacks
- Permit only a small subset of syscalls to be used in order to reduce the
  overall attack surface (making it harder for attackers to escape the sandbox)

Most distributions don't have nsjail packages yet, so we'll need to build from
source. We'll start with the dependencies (assuming you're on Debian or Ubuntu):

    sudo apt install autoconf bison flex gcc g++ git libprotobuf-dev libtool make pkg-config protobuf-compiler

Next, we'll clone the code and check out the latest release (that's version 2.2
at the time of writing).

    git clone https://github.com/google/nsjail.git
    cd nsjail && git checkout 2.2

Building the project should be as simple as running `make`. This will produce a
`nsjail` binary in the same directory which you can then move to
`/usr/local/bin`.

Some of the kernel features used by nsjail weren't added until kernel 4.6, so
you might have to update your kernel or distribution. nsjail also uses the
`user_namespaces` feature, which is typically disabled. Append the following
line to `/etc/sysctl.conf` to enable it:

    kernel.unprivileged_userns_clone=1

Load the configuration change by rebooting your machine or use `sudo sysctl -p`.

## Policy Configuration

nsjail helpfully includes a [sample configuration](https://github.com/google/nsjail/blob/master/configs/imagemagick-convert.cfg)
for ImageMagick's `convert` binary. This offers a good starting point for what
we need. Much of the configuration depends on how your application uses
ImageMagick. In my case, the application is [Mastodon](https://github.com/tootsuite/mastodon),
via the popular [paperclip](https://github.com/thoughtbot/paperclip) gem for
managing file attachments. Paperclip uses ImageMagick by shelling out to the
`convert` and `identify` binaries. That's not a particularly clean way to use
it, but it happens to make this task a bit easier.

You can skip to the end of this section if you just want a working nsjail
configuration for Mastodon's ImageMagick usage. If you're running into issues
with that configuration, reading this section will probably give you the tools
you need for a fix.

Let's start by looking at the sample configuration. The default values
for things like `time_limit` seem good enough, so let's leave them as-is. Next
are a couple of mount directives which provide access to the file system.
Most of them are read-only (no `rw: true`) and permit access to the ImageMagick
binary and shared libraries. I happen to use a compiled version of ImageMagick
that's located in `/usr/local/bin` rather than `/usr/bin`, so I'll need a mount
for that. We'll also want to permit access to the ImageMagick configuration
files which are located in either `/etc/ImageMagick-6` or `/etc/ImageMagick-7`.

Side note: ImageMagick's policy configuration is another place where you can
greatly reduce your attack surface. [This](https://gist.github.com/patf/5aa5ca53b1589ff403b6dadad447e5bf)
is the configuration I use for Mastodon.

All of that leaves me with the following additional mount directives:

    mount {
      src: "/usr/local/lib"
      dst: "/usr/local/lib"
      is_bind: true
      mandatory: false
    }

    mount {
      src: "/usr/local/bin/identify"
      dst: "/usr/local/bin/identify"
      is_bind: true
      mandatory: false
    }

    mount {
      src: "/etc/ImageMagick-6"
      dst: "/etc/ImageMagick-6"
      is_bind: true
      mandatory: false
    }

    mount {
      src: "/etc/ImageMagick-7"
      dst: "/etc/ImageMagick-7"
      is_bind: true
      mandatory: false
    }

I also add `mandatory: false` to the existing `/usr/bin/identify` mount. That
way, nsjail doesn't throw an error if `/usr/bin/identify` doesn't exist and I
can go back and forth between compiled and packaged versions of ImageMagick
without having to change the nsjail configuration.

Next, we'll have to figure out where the files are stored while paperclip
processes them. Paperclip helpfully logs every command it runs, so we can just
`grep` for "Command" in our Rails logs and we'll get something like this:

    Command :: file -b --mime '/tmp/8d777f385d3dfec8815d20f7496026dc20171203-9975-dbjvvy.jpeg'
    Command :: identify -format '%wx%h,%[exif:orientation]' '/tmp/8d777f385d3dfec8815d20f7496026dc20171203-9975-9mj1dj[0]' 2>/dev/null
    Command :: identify -format %m '/tmp/8d777f385d3dfec8815d20f7496026dc20171203-9975-9mj1dj[0]'
    Command :: convert '/tmp/8d777f385d3dfec8815d20f7496026dc20171203-9975-9mj1dj[0]' -auto-orient -resize "1280x1280>" -quality 90 -strip '/tmp/72dc008206075ad7e69b00a1e4f2544020171203-9975-1iywevw'

We can see that all the files are located in `/tmp`, so we'll modify the
existing `/tmp` mount to look like this:

    mount {
      src: "/tmp"
      dst: "/tmp"
      rw: true
      is_bind: true
    }

While we're at it, let's also remove the entire `/Documents` mount — we won't be
needing that.

The final section of the sample configuration is where we define our syscall
filters. The sample configuration uses a blacklist approach which causes the
process to be killed if it uses the `ptrace`, `process_vm_readv` or
`process_vm_writev` syscalls. That's better than nothing, but we can do better
by using a whitelist of syscalls that we know ImageMagick needs, and killing the
process if any other syscall is used.

Getting a list of the required syscalls is a bit involved. We can start by using
`strace -qcf` followed by some of the commands we observed in our Rails log,
using a couple of sample images in various formats. Our goal is to exercise all
of the code paths ImageMagick will run in production, so make sure you use all
the image formats and command variations you can find in your log. You might run
something like:

    strace -qcf convert '/tmp/input.png' -auto-orient -resize "1280x1280>" -quality 90 -strip '/tmp/output.png'

This will produce output similar to this:

    % time     seconds  usecs/call     calls    errors syscall
    ------ ----------- ----------- --------- --------- ----------------
      0.00    0.000000           0        43           read
      0.00    0.000000           0         3           write
      0.00    0.000000           0        65        22 open
      0.00    0.000000           0        43           close
      0.00    0.000000           0        12         5 stat
      0.00    0.000000           0        51           fstat
      0.00    0.000000           0         9           lseek
      0.00    0.000000           0        76           mmap
      0.00    0.000000           0        58           mprotect
      0.00    0.000000           0         7           munmap
      0.00    0.000000           0         8           brk
      0.00    0.000000           0        11           rt_sigaction
      0.00    0.000000           0        19           rt_sigprocmask
      0.00    0.000000           0        31        29 access
      0.00    0.000000           0         1           execve
      0.00    0.000000           0         2           getdents
      0.00    0.000000           0         2           getrlimit
      0.00    0.000000           0         1           sysinfo
      0.00    0.000000           0        14           times
      0.00    0.000000           0         1           arch_prctl
      0.00    0.000000           0         1           futex
      0.00    0.000000           0         1           sched_getaffinity
      0.00    0.000000           0         1           set_tid_address
      0.00    0.000000           0         1           set_robust_list
    ------ ----------- ----------- --------- --------- ----------------
    100.00    0.000000                   461        56 total

We're interested in the syscall column, giving us a first set of syscalls
for our seccomp-bpf policy. Let's change the policy to use `DEFAULT KILL` and
insert the extracted (comma-separated) syscalls:

    seccomp_string: "POLICY imagemagick_convert {"
    seccomp_string: "  ALLOW {"
    seccomp_string: "    read, write, open, close, newstat, newfstat,"
    seccomp_string: "    ... more syscalls ..."
    seccomp_string: "  }"
    seccomp_string: "}"
    seccomp_string: "USE imagemagick_convert DEFAULT KILL"

`strace` uses a slightly different naming convention for some syscalls, so we'll
need to convert those manually. nsjail uses the [Kafel](https://github.com/google/kafel)
language for its syscall filtering specification, so we'll use
[the source file containing all syscalls](https://github.com/google/kafel/blob/master/src/syscalls/amd64_syscalls.c)
as a reference. `stat` is called `newstat` in Kafel, `fstat` is `newfstat`, etc.

Let's store what we have so far in a file in `/etc/nsjail/imagemagick-convert.cfg`
and see if we can successfully run `convert` within nsjail:

    nsjail --config /etc/nsjail/imagemagick-convert.cfg -- /usr/bin/convert '/tmp/input.png' -auto-orient -resize "1280x1280>" -quality 90 -strip '/tmp/output.png'

If you missed a syscall, or if `strace` did (don't ask me why - it happens),
you'll see something like this in the output:

    [W][1047] subprocSeccompViolation():258 PID: 1048 commited a syscall/seccomp violation and exited with SIGSYS

Finding the syscall that caused the violation can be done by using
`grep SECCOMP` on your syslog or audit log. That should produce a log line like
this:

    type=SECCOMP msg=audit(1512341279.874:80142): auid=1000 uid=1000 gid=1000 ses=3 pid=1048 comm="convert" exe="/usr/bin/convert" sig=31 arch=c000003e syscall=158 compat=0 ip=0x7fa87097dbb8 code=0x0

Now we know the missing syscall has the number 158, which we can translate back
to `arch_prctl` using the [Kafel source file from earlier](https://github.com/google/kafel/blob/master/src/syscalls/amd64_syscalls.c).

You'll probably end up doing this a couple of times before you end up with a
working configuration. This is the final syscall policy I ended up with:

    seccomp_string: "POLICY imagemagick_convert {"
    seccomp_string: "  ALLOW {"
    seccomp_string: "    read, write, open, close, newstat, newfstat,"
    seccomp_string: "    newlstat, lseek, mmap, mprotect, munmap, brk,"
    seccomp_string: "    rt_sigaction, rt_sigprocmask, pwrite64, access,"
    seccomp_string: "    getpid, execve, getdents, unlink, fchmod,"
    seccomp_string: "    getrlimit, getrusage, sysinfo, times, futex,"
    seccomp_string: "    arch_prctl, sched_getaffinity, set_tid_address,"
    seccomp_string: "    clock_gettime, set_robust_list, exit_group,"
    seccomp_string: "    clone, getcwd, pread64"
    seccomp_string: "  }"
    seccomp_string: "}"
    seccomp_string: "USE imagemagick_convert DEFAULT KILL"

The full configuration for the `convert` binary can be found [here](https://gist.github.com/patf/d4d533e3dd8ff981667405059df99b6b#file-imagemagick-convert-cfg).
The same gist also includes a configuration for the `identify` binary.

## Caging the Elephant

We now have a working nsjail configuration, but there's one thing left to do:
Getting Mastodon to use it. This is where paperclip shelling out to ImageMagick
works in our favor — we'll just create our own `convert` command that runs
ImageMagick within a sandbox. Let's create `/usr/local/bin/nsjail-wrapper/convert`
with the following content:

    #!/usr/bin/env bash
    nsjail --quiet --config /etc/nsjail/imagemagick-convert.cfg -- /usr/bin/convert "$@"

Make sure to adjust the path from `/usr/bin/convert` if you use a compiled
version of ImageMagick, and `chmod +x` the wrapper file.

Finally, we'll need to get Mastodon to use this file rather than the one located
in `/usr/bin` or `/usr/local/bin`. We do that by adding the following
environment variable to the systemd services that run Mastodon:

    Environment="PATH=/usr/local/bin/nsjail-wrapper:/usr/local/bin:/usr/bin:/bin"

If you're following the default setup instructions for Mastodon, you'll want to
add that line to both `/etc/systemd/system/mastodon-sidekiq.service` and
`/etc/systemd/system/mastodon-web.service`.

Reload systemd, restart the two services and you're done:

    sudo systemctl daemon-reload
    sudo systemctl restart mastodon-sidekiq
    sudo systemctl restart mastodon-sidekiq

It's a good idea to periodically check your syslog (or audit log) for the string
"SECCOMP" after you deploy this, or to have monitoring alert you to a match.
Certain versions or configurations of ImageMagick might use syscalls that aren't
included in my policy, or you might deal with images that trigger a code path I
haven't run into yet. Remember that a policy violation might also be due to a
malicious file, so be careful when adjusting the policy.

## PoC > GTFO

It's probably a good idea to test if our sandbox is working as intended.
To do that, we'll use the [Proof of Concept](https://github.com/ImageTragick/PoCs)
available for the ImageTragick vulnerability, with some small adjustments to
make it work in `/tmp`. We'll need to build a vulnerable version of ImageMagick.
I went with 6.8.5-10:

    convert -version
    Version: ImageMagick 6.8.5-10 2017-12-04 Q16 http://www.imagemagick.org
    Copyright: Copyright (C) 1999-2013 ImageMagick Studio LLC
    Features: DPC OpenMP Modules
    Delegates: mpeg fontconfig freetype jbig jng jpeg lzma png ps x xml zlib

Running the PoC without having `/usr/local/bin/nsjail-wrapper` in my path,
I get the following result:

    ./test.sh
    testing read
    UNSAFE

    testing delete
    UNSAFE

    testing http with local port: 27279
    SAFE

    testing http with nonce: 46648d3b
    SAFE

    testing rce1
    UNSAFE

    testing rce2
    UNSAFE

    testing MSL
    UNSAFE

Evidently we're vulnerable to some parts of ImageTragick. Next, let's add
`/usr/local/bin/nsjail-wrapper` back to our path and try again:

    ./test.sh
    testing read
    SAFE

    testing delete
    SAFE

    testing http with local port: 45326
    SAFE

    testing http with nonce: 0fce39e0
    SAFE

    testing rce1
    SAFE

    testing rce2
    SAFE

    testing MSL
    SAFE

Looks like we successfully mitigated ImageTragick! Our logs shows
a bunch of lines like the following — the exploit code is trying to use the
`msync` syscall and is subsequently killed:

    type=SECCOMP msg=audit(1512348449.807:88531): auid=1000 uid=1000 gid=1000 ses=3 pid=5675 comm="identify" exe="/usr/local/bin/identify" sig=31 arch=c000003e syscall=26 compat=0 ip=0x7f6538695760 code=0x0

## Performance Impact

Measuring the time it takes for a simple JPEG attachment to be processed and
stored by paperclip, the average went from about 650 ms to 2100 ms.
I suspect that most of the increase is due to paperclip shelling out to
ImageMagick, which forces nsjail to build a new sandbox for every invocation.
A daemon handling the conversion of many images would likely perform
significantly better, perhaps even with no noticeable impact.

There is definitely room for improvement here, but given that image conversion
as a whole barely makes a dent in the overall CPU budget of this service and
that media uploads aren't an area where users will get too frustrated because
they'll have to wait an additional second, it's an acceptable trade-off.
