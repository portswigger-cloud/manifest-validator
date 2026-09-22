# Security policy

## Reporting a vulnerability

Report it privately, through GitHub's private vulnerability reporting on this
repository: **Security → Report a vulnerability**. That opens an advisory only
the maintainers can see.

Please do not open a public issue for a vulnerability, and do not test against
PortSwigger infrastructure — this repository is the service's source, not a
deployment you are authorised to probe.

## Scope

This service is deployed only inside PortSwigger's clusters, reachable only by
its one internal caller, and holds no credentials. A report is most useful when
it concerns the code here rather than our deployment of it: the tar reader, the
digest, how a verdict is decided, or a way to make a check pass without having
checked anything.

That last one is the failure this service exists to prevent, and it is the
finding we most want to hear about.

## What to expect

We will acknowledge a report and tell you whether we consider it in scope. We
run no bug bounty for this repository.
