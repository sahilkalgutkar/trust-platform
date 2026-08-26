# trust-platform

A multi-tenant identity and entitlements platform, written from the protocol up: an OpenID Connect
provider, a Zanzibar-style relationship-based authorization service, and a tamper-evident audit log.

I build identity infrastructure for a living and wanted a version of that work I could actually show
someone — so nothing here wraps Spring Security's OAuth support or an authorization SDK. The
interesting part of this domain is the reasoning behind each rule, and you cannot show that by
configuring somebody else's library.

Java 21, Spring Boot 3.3, PostgreSQL, Redis, Kafka. Multi-module Maven, one database per service.
