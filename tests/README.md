The `application_client` directory contains the minimalist python client for crafting and sending APDUs to the application.

The `standalone` directory contains the functional tests of the application, when it is started from the Dashboard of the device.

The `vectors` directory holds signature payloads rendered by upstream gno with `tools/vectors`. The functional tests and `host-tests` both replay them.
