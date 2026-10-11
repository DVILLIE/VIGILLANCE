# D'Vielle actual executable network containment resolution

## Observed failure and cause

The first Administrator-approved installed-helper experiment created a rule for
`C:\Program Files\DVielle\.venv\Scripts\python.exe`. Both new TCP connections
and an existing verified TLS connection continued. Conditional restoration passed.
This failed result remains in `ACTUAL_NETWORK_SCOPE_FAILED_ACCEPTANCE_2026-10-10.json`.

An actual process query found that the network-owning executable was
`C:\Program Files\DVielleRuntime\Python314\python.exe`. The virtual environment
executable is a launcher. [Python's official documentation](https://docs.python.org/3.14/library/venv.html)
confirms that Windows virtual environments use redirectors.

## Corrected actual experiment

The reviewed immutable acceptance command explicitly granted the actual process
image, obtained through `psutil.Process().exe()`. It did not expand an existing grant.
The scope covers all instances of this executable to the selected IPv4 address,
not just one PID. The installed service and runtime were unchanged.

At 13:45 UTC on 10 October 2026, connectivity to 151.101.0.223:443 succeeded before
application. After the helper verified its rule, two new connections failed with
Windows error 10013 and the existing TLS connection failed with error 10054.
Owned-rule restoration succeeded and the subsequent connection succeeded.
The complete protected result was copied to
`ACTUAL_IMAGE_NETWORK_ACCEPTANCE_2026-10-10.json`.

## Source change and remaining acceptance

Local assessment owner observations now include the actual executable image and
explain that executable-path policy affects all instances. Default exports already
remove the entire owner observation, including this private path. These source
changes are not yet activated in the protected installation.

This is actual bounded IPv4/TCP evidence. IPv6, UDP, QUIC, VPN, proxies, arbitrary
children, competing policy and deployed crash recovery still require their own
acceptance. Packet-drop provider attribution was not measured. The project plan
is not fully completed by this experiment.
