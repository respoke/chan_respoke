## About

The Respoke Modules for Asterisk (RMA) is a collection of libraries that provide
the necessary tools in order to allow communication between Asterisk and the
Respoke service.

## Licensing

The Respoke Modules for Asterisk (RMA) is distributed under the GNU General
Public License version 2. The GPL (version 2) is included in this source tree
in the file COPYING.

## Modules

The RMA is made up of several installable modules which can be found under a
directory structure similar to Asterisk.  For instance, the channel driver is
found under the 'channels' directory and the resource modules (res_respoke)
are contained in the 'res' directory.

## Dependencies

The following programs and/or libaries need to be installed before compiling
and installing the RMA:

Asterisk (>= version 13.0.0)
libcurl

## Building and Installing

In order to build the RMA without errors the necessary dependencies need to be
installed prior to compiling.  Once the dependencies have been installed, run
the following within the projects top level directory from the command line:

    make

Note, that if Asterisk has been installed to a non default directory (e.g. it
has not been installed under '/usr') then the following flag can be set in order
to specify the asterisk install directory:

    make AST_INSTALL_DIR=/path/to/asterisk/install

If all the modules built successfully, issue the following to install the RMA:

    make install

## Configuration

A 'respoke.conf' configuration file also needs to be constructed and saved to
the Asterisk installation configuration directory (typically /etc/asterisk/).
The respoke configuration file follows the same rules and similar patterns to
that of a typical Asterisk configuration file.  See the 'respoke.conf.sample'
file for more information.


