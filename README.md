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

- libcurl
- pjproject
- - Asterisk (>= version 13.0.0)
  - Required modules: res_rtp_asterisk

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

## Asterisk Channel Variables

You can use the following Respoke session information to manage them inside the asterisk channel:

- RESPOKE_SESSION_LOCAL
- RESPOKE_SESSION_LOCAL_TYPE
- RESPOKE_SESSION_LOCAL_CONNECTION
- RESPOKE_SESSION_REMOTE
- RESPOKE_SESSION_REMOTE_TYPE
- RESPOKE_SESSION_REMOTE_CONNECTION
- RESPOKE_SESSION_REMOTE_APPID
- RESPOKE_SESSION_ID

Here it is a dialplan example in order to pass the "RESPOKE_SESSION_REMOTE" inside an asterisk channel variable:

    exten => your_respoke_endpoint,1,Answer()
    same => n,NoOp(RESPOKE METADATA: ${RESPOKE_SESSION_REMOTE})
    same => n,Ringing
    same => n,Wait(8)
    same => n,Playback(welcome)
    same => n,SayAlpha(${RESPOKE_SESSION_REMOTE})
    same => n,Dial(SIP/300)
    same => n,Hangup()

In the above example, the "RESPOKE_SESSION_REMOTE" information is played back to the caller using the Asterisk application SayAlpha.

## AMI

The following Event is available on to the Asterisk Manager Interface:

**Event: RespokeSession**

##### Example:

    Event: RespokeSession
    Privilege: system,all
    channel: RESPOKE/anonymous-00000006
    id: 98B0F7D7-6AEC-4037-8250-8C5DFA7A2C11
    local: your_respoke_endpoint
    local_type: web
    local_connection:
    remote: ORDER12345
    remote_type: web
    remote_connection: 01749CDF-4BB0-41DB-8D52-30D25954D41A
    remote_appid:

In the above example, the AMI "RespokeSession" Event includes the respoke session information, in particular the remote field.
