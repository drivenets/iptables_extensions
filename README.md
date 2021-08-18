# iptables_extensions
Contains custom iptables extensions (matches/targets) used in DNOS.

# Prerequisites
1. `sudo apt install iptables-dev`
2. Make sure the machine you're compiling at is running the same kernel and iptables version as what DNOS is running (5.4.0-73-generic and 1.8.4 respectively, as of the time of this writing).

# Building
* Build all extensions: `make all`
* Clean all extensions: `make clean`

These iterate and build/clean all the extensions under the `extensions/` directory.

The output of each extension is:
1. A `.ko` file - The kernel module responsible for the heavy lifting of the extension (registers to netfilter, processes skbs etc).
2. A `.so` file - A userspace plugin for the `iptables` program. Mostly responsible for argument parsing.

# Tree structure
1. extensions/
    * Contains all the extensions, each in its own directory.
2. out/
    * The build process will place here the .so and .ko files, each in the matching extensions' directory.
3. help/
    * Contains helpful tutorials.

# Installing new extensions
1. Copy the .so files into `/usr/lib/x86_64-linux-gnu/xtables`
2. `insmod` the .ko files

# But Lahav Senapi, how do I write a new extension myself?
Check the `help/` directory. `help/Netfilter_Modules.pdf` is a pretty good one.
