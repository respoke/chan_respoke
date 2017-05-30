## About
[![Gitter](https://badges.gitter.im/Join Chat.svg)](https://gitter.im/respoke/chan_respoke?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

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

- libcurl
- [pjproject][]
- Asterisk (>= version 13.0.0)
  - Required modules: `res_rtp_asterisk`

 [pjproject]: https://wiki.asterisk.org/wiki/x/J4GLAQ

### Certified Asterisk

Asterisk versions prior to 13.2.0, including 13.1-cert2, have a [DTLS issue][]
when connecting to Respoke, caused by a security patch in OpenSSL 1.0.1k. Please
upgrade to a newer version of Asterisk, or apply [this patch][] to correct the
issue with DTLS.

 [DTLS issue]: https://issues.asterisk.org/jira/browse/ASTERISK-24711
 [this patch]: https://code.asterisk.org/code/rdiff/asterisk?csid=e0461290d0c35e643070c8ed98f4b7e95345a708&u&N

### PJSIP configuration

WebRTC endpoints may offer more ICE candidates than PJSIP's default limits.
These can be configured when PJSIP is compiled, and Asterisk must be recompiled
when they are changed.

When building PJSIP from source, immediately after running `./configure`, create
the file `pjlib/include/pj/config_site.h` with the following contents. The
actual values for `PJ_ICE_MAX_CAND` and `PJ_ICE_MAX_CHECKS` may vary depending
on your use case, but these are some good defaults for WebRTC.

```c
#ifndef __PJ_CONFIG_SITE_H__
#define __PJ_CONFIG_SITE_H__

/* Defaults too low for WebRTC */
#define PJ_ICE_MAX_CAND 32
#define PJ_ICE_MAX_CHECKS (PJ_ICE_MAX_CAND * 2)

#endif /* __PJ_CONFIG_SITE_H__ */
```

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

### DTLS Certificate

The usual Asterisk script for generating a certificate (`ast_tls_cert`)
generates a certificate chain, which can cause DTLS packets to be larger than
the typical MTU. This fragmentation can cause data loss in some networks.

It is recommended to install a small self-signed certificate instead. This can
be done by `make install-keys`, which creates `/etc/asterisk/keys/respoke.pem`.

## Example

A basic example configuration and setup can be found under the "example"
directory. To install the example execute the following command (Note, that
this will overwrite any "respoke.conf" and "extensions.conf" files currently
residing under the Asterisk install directory. Be sure to back up any files
before proceeding):

    make install-example

This installs an example respoke configuration along with a simple dialplan as
well as some sounds files used for playback. An example certificate authority
and client certificate are also installed in order to facilitate audio between
endpoints (*WARNING* - These files are for example use only and should not be
used in a production environment).

Once installed, edit the "respoke.conf" file and set the "app_id" option under
the "app" section to a valid respoke app-id. After starting Asterisk, and
sending an offer/call via Respoke from a properly constructed application to
one of the configured endpoints (basic or mixdown) the appropriate audio should
be heard and the call hung up.

To uninstall all files associated with the example issue the following command:

    make uninstall-example

## Building for Distribution

To build a tar to attach to the github release, run `make dist`. Note: using
the Makefile checks for Asterisk to be installed on the system. If you don't
have Asterisk on your system but still need to cut a new release, you can
run `./build_tools/make_version && ./build_tools/make_dist` to generate the
tar with the appropriate .version file in it.
