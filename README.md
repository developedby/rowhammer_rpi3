# rowhammer_rpi3
Simple Rowhammer attack PoC for Raspberry Pi 3B+

## Usage
* Download `rowhammer.c` on the Rapsberry Pi with `git clone https://github.com/developedby/rowhammer_rpi3.git` or your preferred method.
* Compile with `gcc rowhammer.c -o rowhammer`.
* Execute with `sudo ./rowhammer`, follow the instructions of the CLI interface.

This code is based on [https://github.com/0x5ec1ab/rowhammer_armv8], trimmed down to only the essential parts. It also has some slight modifications to work on Raspberry Pi instead of their board.

*This was only tested on the Raspberry Pi 3B+ and will most likely not work on boards that have different memory chips.*

## Authors
* [Nicolas Abril](https://github.com/developedby)
* [Matteo Isoldi](https://github.com/bOhYee)
* []()
* []()

Original code from https://github.com/0x5ec1ab/rowhammer_armv8
