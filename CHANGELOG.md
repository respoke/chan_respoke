# Change Log

All notable changes to this project will be documented in this file.

## 1.3.0 - 2016-10-21

- `make all` will no longer overwrite a valid `.version` file with
the value 'unknown'. This will help chan_respoke report the correct
sdk version in its request headers when connecting to Respoke.

- Updates for Asterisk 14 compatibility.
