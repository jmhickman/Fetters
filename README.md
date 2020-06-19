# Fetters

F# re-implementation of Ghostpack/Seatbelt, a Windows enumeration program for red teams and system administrators.

## Purpose

This project was for me to get comfortable with F# by implementing a program that I liked. Seatbelt is not too big, not too small, and had sufficient complexity that I would always be challenged while writing it.

It is _NOT_ a 100% compliant implementation of Seatbelt! 

Because the primary purpose was to learn F#, there are bits and bobs that I chose to not port because I found the particular piece of functionality to not be very compelling vs the number of lines of code to get it going. I'd estimate that Fetters does about 93-94% of what Seatbelt does. There are things that Fetters does that Seatbelt doesn't do, so it's not even an apples to apples comparison!

Also, Seatbelt got a massive re-write and update about 2 weeks before I wrapped up the program. This version of Fetters targetted the old version of Seatbelt, not the shiny new version. I may circle back around later and add checks. If I do so, it will probably be because I've gained enough experience to make substantial changes to Fetters in order to make it more idiomatic.

## Credits

Please check the CREDITS file for code acknowledgements.

## Improvements

I'm likely to ignore PRs, at least for the time being. This represented 2 months of work in my free time to do, and I'm quite ready to put it down and work on other things. If you want to see an improvement, feel free to submit a PR, but don't be surprised if I don't immediately respond.

## Requirements

I've tested Fetters on 64bit Windows **10** 1703 and later, Server **2012**, Windows **7** and Windows **8.1**. **Net 4.61 or later** must be present. While many checks should work if run in 32 bit mode, there is PInvoke code that, for various reasons, has statically set pointer math that will probably make things angry with smaller IntPtrs. I don't have a 32bit Windows lying around to check.

## Build

You should be able to import the Solution and simply build it. Costura is in use in order to generate a singular binary. It's kind of fat, sorry about that. FSharp.Core.dll is not distributed in the GAC because Microsoft seems to forget about it year after year.

## Use

Fetters is meant to be run at the console directly. There isn't an explicit namespace in use, so how it would interact with post exploitation frameworks via a `execute-assembly`-like command is anyone's guess. Fortunately, Windows Defender has sniffed it and largely ignored it, so until someone uses it for evil it might stay 'clean.'

The program will take any number of function names in a sequence to run. You can see a terse description of each by running `-hh`. Or you may simply specify `system` or `user` to run a pre-set series of checks. I recommend `getbasicinfo` by itself to start.
