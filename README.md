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
* [Massimiliano Di Todaro](https://github.com/mditodaro)
* [Diego Porto](https://github.com/akhre)

Original code from [https://github.com/0x5ec1ab/rowhammer_armv8]. It is proprietary, but following Github's [Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service#5-license-grant-to-other-users), any user is allowed to view and fork public repositories inside Github.

This material was originally developed as part of an assignment of the Operating systems for embedded systems course delivered at Politecnico di Torino by Prof. Stefano Di Carlo.
