# commpact

Run `firsttimesetup.sh` to download, configure, and build everything.
Do not run `firsttimesetup.sh` multiple times.

Run `rebuild.sh` to rebuild everything.

You will need to source `setenv` before running veins (Veins invokes SUMO).
~~~~
. setenv
~~~~
This sets the proper environment variables for veins to find OMNeT++ and for SUMO to find the Enclave.
