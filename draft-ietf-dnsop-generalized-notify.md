---
title: Generalized DNS Notifications
abbrev: Generalized Notifications
docname: draft-ietf-dnsop-generalized-notify-latest
date: {DATE}
category: std

ipr: trust200902
area: Internet
workgroup: DNSOP Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: J. Stenstam
    name: Johan Stenstam
    organization: The Swedish Internet Foundation
    email: johan.stenstam@internetstiftelsen.se
 -
    ins: P. Thomassen
    name: Peter Thomassen
    org: deSEC, Secure Systems Engineering
    email: peter@desec.io
 -
    ins: J. Levine
    name: John Levine
    org: Standcore LLC
    email: standards@standcore.com

normative:

informative:

--- abstract

This document generalizes and extends the use of DNS NOTIFY (RFC 1996) beyond
conventional zone transfer hints, to allow triggering other types of actions
via the DNS that were previously lacking a trigger mechanism.
Notifications merely nudge the receiver to initiate a predefined action promptly
(instead of on a schedule); they do not alter the action itself
(including any security checks it might employ).

To enable this functionality, a method for discovering the receiver endpoint
for such notification messages is introduced, via the new DSYNC record type.
Notification types are recorded in a new registry, with initial support for
parental NS and DS record updates including DNSSEC bootstrapping.

TO BE REMOVED: This document is being collaborated on in Github at:
[https://github.com/peterthomassen/draft-ietf-dnsop-generalized-notify](https://github.com/peterthomassen/draft-ietf-dnsop-generalized-notify).
The most recent working version of the document, open issues, etc. should all be
available there.  The authors (gratefully) accept pull requests.

--- middle

# Introduction

Traditional DNS notifications {{!RFC1996}}, which are here referred to as
"NOTIFY(SOA)", are sent from a primary server to a secondary server to
minimize the latter's convergence time to a new version of the
zone. This mechanism successfully addresses a significant inefficiency
in the original protocol.

Today similar inefficiencies occur in new use cases, in particular delegation
maintenance (DS and NS record updates). Just as in the NOTIFY(SOA) case, a new
set of notification types will have a major positive benefit by
allowing the DNS infrastructure to completely sidestep these
inefficiencies. For additional context, see {{context}}.

Although this document primarily deals with applying generalized notifications
to the delegation maintenance use case, future extension for other applications
(such as multi-signer key exchange) is possible.

No DNS protocol changes are introduced by this document. The mechanism
instead makes use of a wider range of DNS messages allowed by the protocol.

Readers are expected to be familiar with DNSSEC {{!RFC9364}}, including
{{?RFC6781}}, {{!RFC7344}}, {{!RFC7477}}, {{?RFC7583}}, {{!RFC8078}},
{{?RFC8901}}, and {{!RFC9615}}.
DNS-specific terminology can be found in {{!RFC9499}}.

## Design Requirements for Delegation Maintenance

When the parent operator is interested in notifications for delegation
maintenance (such as DS or NS update hints), a service will need to be
made available for accepting these notifications. Depending on the
context, this service may be run by the parent operator themselves,
or by a designated entity who is in charge of handling the domain's
delegation data (such as a domain registrar).

It seems desirable to minimize the number of steps that the notification sender
needs to perform in order to figure out where to send the NOTIFY. This suggests
that the lookup process be ignorant of the details of the parent-side
relationships (e.g., whether there is a registrar or not). This is
addressed by parameterizing the lookup with the name of the child. The
parent operator may then (optionally) announce the notification endpoint
in a delegation-specific way, by publishing it at a child-specific name.
(A catch-all endpoint may be indicated by wildcarding.)

The solution proposed here is thus for the parent operator to publish
the address where someone listens for notifications, in a child-specific
way (see {{signaling}}). Potential senders can easily determine the name
of the parent and then look up that information (see {{discovery}}).

## Requirements Notation

{::boilerplate bcp14}

# DSYNC RR Type {#dsyncrdtype}

This section defines the DSYNC RR type which is subsequently used for
discovering notification endpoints.

## Wire Format

The DSYNC RDATA wire format is encoded as follows:

                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | RRtype                        | Scheme        | Port
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    | Target ...  /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-/

RRtype
: The type of generalized NOTIFY that this DSYNC RR defines the
desired target address for (see "Resource Record (RR) TYPEs" IANA
registry). For now, only CDS and CSYNC are supported values, with
the former indicating an updated CDS or CDNSKEY record set.

Scheme
: The mode used for contacting the desired notification address. This is an
8-bit unsigned integer. Records with value 0 (null scheme) are ignored by consumers.
Value 1 is described in this document, and values 128-255 are reserved for
private use.  All other values are currently unassigned.

Port
: The port on the target host of the notification service. This
is a 16-bit unsigned integer in network byte order. Records with
value 0 are ignored by consumers.

Target
: The fully-qualified, uncompressed domain name of the target host
providing the service of listening for generalized notifications of the
specified type. This name MUST resolve to one or more address records.

## Presentation Format

The presentation format of the RDATA portion is as follows:

- The RRtype field is represented as a mnemonic from the "Resource
  Record (RR) TYPEs" registry.

- The Scheme field is represented by its mnemonic if assigned (see
  {{schemeregistry}}), otherwise as an unsigned decimal integer.

- The Port field is represented as an unsigned decimal integer.

- The Target field is represented as a \<domain-name\> ({{!RFC1035,
  Section 5.1}}).

## Semantics

For now, the only scheme defined is 1 (mnemonic: NOTIFY). It indicates that
when a new CDS/CDNSKEY (or CSYNC) RRset is published, a NOTIFY message (see
{{cnotify}}) should be sent to the address and port listed in the corresponding
DSYNC record, using conventional {{!RFC1035}} DNS transport.

Example (for the owner names of these records, see {{signaling}}):

    IN DSYNC  CDS   NOTIFY 5359 cds-scanner.example.net.
    IN DSYNC  CSYNC NOTIFY 5360 csync-scanner.example.net.

Should a need for other mechanisms arise, other schemes may be defined
to deal with such requirements using alternative logic.

Schemes are independent of RRtype. They merely specify a method of
contacting the target (whereas the RRtype is part of the notification
payload).


# Publication of Notification Targets {#signaling}

To use generalized notifications, it is necessary for the sender to know
where to direct each NOTIFY message. This section describes the
procedure for discovering that notification target.

Note that generalized NOTIFY messages are but one mechanism for
improving the efficiency of automated delegation maintenance. Other
alternatives, such as contacting the parent operator via an API or
DNS Update ({{!RFC2136}}), may (or may not) be more suitable in
individual cases. Like generalized notifications, they similarly require
a means for discovering where to send the API or DNS Update requests.

As the scope for the publication mechanism is wider than only to
support generalized notifications, a unified approach that works
independently of the notification method is specified in this section.

Parent operators participating in the discovery scheme for the purpose of
delegation maintenance notifications MUST publish endpoint information
using the record type defined in {{dsyncrdtype}} under the `_dsync`
subdomain of the parent zone, as described in the following subsections.

There MUST NOT be more than one DSYNC record for each combination of
RRtype and Scheme.
It is RECOMMENDED to secure zones containing DSYNC records with DNSSEC.

For practical purposes, the parent operator MAY delegate the `_dsync`
domain as a separate zone, and/or synthesize records under it. If
child-specificity is not needed, the parent can publish a static
wildcard DSYNC record.

## Wildcard Method

If the parent operator itself performs CDS/CDNSKEY or CSYNC processing
for some or all delegations, or wants to forward notifications to some
other party, a default notification target may be specified as follows:

    *._dsync.example.  IN DSYNC  CDS   scheme port target
    *._dsync.example.  IN DSYNC  CSYNC scheme port target

To accommodate indirect delegation management models, the
designated notification target may relay notifications to a third party
(such as the registrar, in ICANN's model). The details of such
arrangements are out of scope for this document.

If for some reason the parent operator cannot publish wildcard records,
the wildcard label may be dropped from the DSYNC owner name (i.e., it
may be published at the `_dsync` label instead). This practice requires
an additional step during discovery (see {{discovery}}), and is
therefore NOT RECOMMENDED.

## Child-specific Method

It is also possible to publish child-specific records where the parent zone's
labels are stripped from the child's FQDN and the result is used in place of
the wildcard label.

As an example, consider a registrar offering domains like
`child.example`, delegated from `example` zone. If the registrar
provides the notification endpoint, e.g., `rr-endpoint.example:5300`,
the parent may publish this information as follows:

    child._dsync.example.  IN DSYNC  CDS NOTIFY 5300 rr-endpoint.example.


# Delegation Maintenance: CDS/CDNSKEY and CSYNC Notifications {#cnotify}

Delegation maintenance notifications address the inefficiencies related
to scanning child zones for CDS/CDNSKEY records
{{!RFC7344}}{{!RFC8078}}{{!RFC9615}}. (For an overview of the issues,
see {{context}}.)

NOTIFY messages for delegation maintenance MUST be formatted as described in
{{!RFC1996}}, with the `qtype` field replaced as appropriate.

To address the CDS/CDNSKEY dichotomy, the NOTIFY(CDS) message (with
`qtype=CDS`) is defined to indicate any child-side changes pertaining
to an upcoming update of DS records.
As the child DNS operator generally is unaware of whether the parent
side consumes CDS records or prefers CDNSKEY, or when that policy
changes, it seems advisable to publish both types of records,
preferably using automation features of common authoritative nameserver
software for ensuring consistency.

Upon receipt of NOTIFY(CDS), the parent-side recipient (typically, registry or
registrar) SHOULD initiate the same DNS lookups and verifications for
DNSSEC bootstrapping {{!RFC9615}} or DS maintenance
{{!RFC7344}}{{!RFC8078}} that would otherwise be triggered based on a
timer.

The CSYNC {{!RFC7477}} inefficiency may be similarly treated, with the
child sending a NOTIFY(CSYNC) message (with `qtype=CSYNC`) to an address
where the parent operator (or a designated party) is listening for CSYNC
notifications.

In both cases the notification will speed up processing times by
providing the recipient with a hint that a particular child zone has
published new CDS, CDNSKEY and/or CSYNC records.

## Endpoint Discovery {#discovery}

To locate the target for outgoing delegation maintenance notifications,
the notification sender MUST perform the following steps:

1. Construct the lookup name, by inserting the `_dsync` label after the
   first label of the delegation owner name.

2. Perform a lookup of type DSYNC for the lookup name, and validate the
   response if DNSSEC is enabled. If a positive DSYNC answer results,
   return it.

3. If the query resulted in a negative response:

   - If the response's SOA record indicates that the parent is more than
     one label away from the `_dsync` label, construct a new lookup name
     by inserting the `_dsync` label into the delegation owner name just
     before the parent zone labels inferred from the negative response,
     and go to step 2.

     For example, `city.ise.mie.jp` is delegated from `jp` (and not
     from `ise.mie.jp` or `mie.jp`!). The initial DSYNC query relating
     to it is thus directed at `city._dsync.ise.mie.jp`. This is
     expected to result in a negative response from `jp`, and another
     query for `city.ise.mie._dsync.jp` is then required.

   - Otherwise, if the lookup name has any labels in front of the
     `_dsync` label, remove them to construct a new lookup name (such
     as `_dsync.jp`), and go to step 2.
     (This is to enable zone structures without wildcards.)

   - Otherwise, return null (no notification target available).

## Sending Notifications

When creating or changing a CDS/CDNSKEY/CSYNC RRset in the child zone,
the DNS operator SHOULD send a suitable notification to one of the
endpoints discovered as described in the previous section.

A NOTIFY message can only carry information about changes concerning one
child zone. When there are changes to several child zones, the sender
MUST send a separate notification for each one.

When a primary name server publishes a new RRset in the child, there
typically is a time delay until all publicly visible copies of the zone
are updated. If the primary sends a notification at the exact time of
publication, there is a potential for CDS/CDNSKEY/CSYNC processing to be
attempted before the corresponding records are served. As a result, a
desired update may not be detected (or appear inconsistent), preventing
it from being applied.

It is therefore RECOMMENDED that the child delays sending notifications
to the recipient until a consistent public view of the pertinent
records is ensured.

### Timeouts and Error Handling

NOTIFY messages are expected to elicit a response from the recipient
({{!RFC1996}} Section 4.7). If no response is received, senders SHOULD
employ the same logic as for SOA notifications ({{!RFC1996}} Sections
3.5 and 3.6).

The recipient's attempt to act upon the delegation update request may
fail for a variety of reasons (e.g., due to violation of the continuity
requirement set forth in {{!RFC7344}} Section 4.1). Such failures may
occur asynchronously, even after the NOTIFY response has been sent.

In order to learn about such failures, senders MAY include an
{{!RFC9567}} EDNS0 Report-Channel option in the NOTIFY message to
request the receiving side to report any errors by making a report query
with an appropriate extended DNS error code as described in
{{!RFC8914}}.
(The prohibition of this option in queries ({{?RFC9567, Section 6.1}}) only
applies to resolver queries and thus does not cover NOTIFY message.)

When including this EDNS0 option, its agent domain MUST be subordinate
or equal to one of the NS hostnames, as listed in the child's delegation
in the parent zone.
This is to prevent malicious senders from causing the NOTIFY recipient
to send unsolicited report queries to unrelated third parties.

### Roles

While the CDS/CDNSKEY/CSYNC processing following the receipt of a NOTIFY
will often be performed by the registry, the protocol anticipates that
in some contexts (especially for ICANN gTLDs), registrars may take on
the task. In such cases, the current registrar notification endpoint may
be published, enabling notifications to be directed to the
appropriate target. The mechanics of how this is arranged between
registry and registrar are out of scope for this document; the protocol
only offers the possibility to arrange things such that from the child
perspective, it is inconsequential how the parent-side parties are
organized: notifications are simply sent to the published address.

Because of the security model where a notification by itself never
causes a change (it can only speed up the time until the next
check for the same thing), the sender's identity is not crucial.
This opens up the possibility of having an arbitrary party (e.g., a
side-car service) send the notifications, enabling this functionality
even before the emergence of native support in nameserver software.

## Processing of NOTIFY Messages for Delegation Maintenance

The following algorithm applies to NOTIFY(CDS) and NOTIFY(CSYNC) processing.

NOTIFY messages carrying notification payloads (records) for
several child zones MUST be discarded, as sending them is an error.

Upon receipt of a (potentially forwarded) valid NOTIFY message for
a particular child zone at the published notification endpoint,
the receiving side (parent registry or registrar) has two options:

  1. Acknowledge receipt by sending a NOTIFY response as described in
     {{!RFC1996}} Section 4.7 (identical to NOTIFY query, but with QR
     bit set and any EDNS0 Report-Channel options removed), and schedule
     an immediate check of the CDS/CDNSKEY/CSYNC RRsets published by that
     particular child zone (as appropriate for the type of NOTIFY received).

     If the NOTIFY message contains an {{!RFC9567}} EDNS0 Report-Channel
     option with an agent domain subordinate or equal to one of the NS
     hostnames listed in the delegation, the processing party SHOULD
     report any errors occurring during CDS/CDNSKEY/CSYNC processing by sending
     a report query with an appropriate extended DNS error code as
     described in {{!RFC8914}}. Reporting may be done asynchronously
     (outside of the NOTIFY transaction).

     When using periodic scanning, notifications preempt the scanning
     timer. If the NOTIFY-induced check finds that the CDS/CDNSKEY/CSYNC RRset
     is indeed new or has changed, the corresponding child's timer may
     be reset and the scanning frequency reduced (e.g., to once a week).
     If a CDS/CDNSKEY/CSYNC change is later detected through scanning (without
     having received a notification), NOTIFY-related state SHOULD be
     cleared, reverting to the default scanning schedule for this child.

     When introducing CDS/CDNSKEY/CSYNC scanning support at the same time
     as NOTIFY support, backwards compatibility considerations
     regarding the scanning interval do not apply; a low-frequency
     scanning schedule MAY thus be used by default in such cases.

  2. Do not act upon the notification. To prevent retries, recipients
     SHOULD acknowledge the notification by sending a NOTIFY response
     even when otherwise ignoring the request, combined with a report
     query if feasible (see above). One reason to do this may be a rate
     limit (see {{security}}), in which case "Blocked" (15) may be a
     suitable extended DNS error code.

Implementing the first option will significantly decrease the
convergence time (between publication of a new CDS/CDNSKEY/CSYNC record in the
child and publication of the resulting DS), thereby providing improved
service for the child.

If, in addition to scheduling an immediate check for the child zone of
the notification, the scanning schedule is also modified to be less
frequent, the cost of providing the scanning service will be reduced.


# Security Considerations {#security}

If an action is triggered by the receipt of a DNS NOTIFY, its execution relies
on the same security model which the receiving party would apply if the action
had been triggered by something else. This is because the notification affects
the action's timing alone. For example, DS bootstrapping is expected to be
performed the same way independently of the type of trigger; this includes all
security and authentication requirements (e.g., {{!RFC9615}}) which the parent
registry/registrar has chosen to apply.

The original NOTIFY specification sidesteps most security issues by not
relying on the information in the NOTIFY message in any way, and instead
only using it to "enter the state it would if the zone's refresh timer
had expired" ({{Section 4.7 of !RFC1996}}).

This security model is reused for generalized NOTIFY messages. It
therefore seems impossible to affect the behaviour of the recipient of
the NOTIFY other than by hastening the timing for when different checks
are initiated.
As a consequence, while notifications themselves can be secured via access
control mechanisms, this is not a requirement.

The receipt of a notification message will, in general, cause the
receiving party to perform one or more outbound queries for the records
of interest (for example, NOTIFY(CDS) will cause CDS/CDNSKEY
queries). When done using standard DNS, the size of these queries is
comparable to that of the NOTIFY messages themselves, rendering any
amplification attempts futile. The number of queries triggered per
notification is also limited by the requirement that a NOTIFY message
can refer to one child only.

However, when the outgoing query occurs via encrypted transport, some
amplification is possible, both with respect to bandwidth and
computational burden. In this case, the usual principle of bounding the
work, even under unreasonable events, applies.

Receivers therefore MUST implement rate limiting for notification
processing. It is RECOMMENDED to configure rate limiting independently
for both the notification's source IP address and the name of the zone
that is conveyed in the NOTIFY message. Rate limiting also mitigates
processing load from garbage notifications.

Alternative solutions (such as signing notifications and validating
their signatures) appear significantly more expensive without tangible
benefit.

In order to facilitate schemes that are authenticated outside of DNSSEC
(such as via SIG(0)), zones containing DSYNC records are not required to
be signed. Spoofed DSYNC responses would prevent notifications from
reaching their legitimate target, and a different party may receive
unsolicited notifications; both effects, however, can also be achieved
in the presence of DNSSEC. The illegitimate target is also enabled to
learn notification contents in real-time, which may be a privacy concern
for the sender. If so, the sender may choose to ignore unsigned DSYNC
records.


# IANA Considerations

**Note to the RFC Editor**: In this section, please replace occurrences of "(this document)" with a proper reference.

## DSYNC RR Type

IANA is requested to update the "Resource Record (RR) TYPEs" registry
under the "Domain Name System (DNS) Parameters" registry group as
follows:

Type
: DSYNC

Value
: 66

Meaning
: Endpoint discovery for delegation synchronization

Reference
: (this document)


## DSYNC Scheme Registration {#schemeregistry}

IANA is requested to create and maintain the following new registry in the
"Domain Name System (DNS) Parameters" registry group:

Name
: DSYNC: Location of Synchronization Endpoints

Assignment Policy
: Expert Review

Reference
: (this document)

The initial contents for the registry are as follows:

| RRtype | Scheme  | Mnemonic | Purpose                | Reference       |
| ------ | ------- | -------- | ---------------------- | --------------- |
|        |       0 |          | Null scheme (no-op)    | (this document) |
| CDS    |       1 | NOTIFY   | Delegation management  | (this document) |
| CSYNC  |       1 | NOTIFY   | Delegation management  | (this document) |
|        |   2-127 |          | Unassigned             |                 |
|        | 128-255 |          | Reserved (private use) | (this document) |

Requests to register additional entries MUST include the following fields:

RRtype
: An RRtype that is defined for use

Scheme
: The mode used for contacting the desired notification address

Mnemonic
: The scheme's shorthand string used in presentation format

Purpose
: Use case description

Reference
: Location of specification or registration source

Registration requests are to be recorded by IANA after Expert Review {{!RFC8126}}.

## _dsync Underscore Name

Per {{!RFC8552}}, IANA is requested to add the following entries to the
"Underscored and Globally Scoped DNS Node Names" registry:

    +---------+------------+-----------------+
    | RR Type | _NODE NAME | Reference       |
    +---------+------------+-----------------+
    | DSYNC   | _dsync     | (this document) |
    +---------+------------+-----------------+

## Expert Reviewer Instructions

This section gives
some general guidelines for what the experts should be looking for,
but they are being designated as experts for a reason, so they should
be given substantial latitude.

Expert reviewers should take into consideration the following points:

- Point squatting should be discouraged.  Reviewers are encouraged
      to get sufficient information for registration requests to ensure
      that the usage is not going to duplicate one that is already
      registered and that the point is likely to be used in deployments.
      The code points tagged as "Private Use" are intended for testing
      purposes and closed environments.  Code points in other ranges
      should not be assigned for testing.

- A specification of a scheme is desirable,
but early assignment before a
      specification is available is also possible.  When
      specifications are not provided, the description provided needs to
      have sufficient information to identify what the point is being
      used for.

- Experts should take into account the expected usage of fields when
      approving point assignment.
The mnemonic will usually be the name of an RRTYPE, and the process that
the notification triggers should have a plausible connection to that RRTYPE.

# Implementation Status

**Note to the RFC Editor**: please remove this entire section before publication.

Johan Stenstam's experimental nameserver implements this draft
(https://github.com/johanix/tdns).

## Child DNS Operator-side

- IronDNS implementation under way

- deSEC implementation under way (Q1/2025)

## Parent-side

- SWITCH (.CH/.LI) implementation is under way.

- .SE/.NU will implement this once it is an RFC.


# Acknowledgements

In order of first contribution or review:
Joe Abley, Mark Andrews, Christian Elmerot, Ólafur Guðmundsson, Paul
Wouters, Brian Dickson, Warren Kumari, Patrick Mevzek, Tim Wicinski,
Q Misell, Stefan Ubbink, Matthijs Mekking, Kevin P. Fleming, Nicolai
Leymann, Giuseppe Fioccola, Peter Yee, Tony Li, Paul Wouters, Roman
Danyliw, Peter van Dijk.

--- back


# Efficiency and Convergence Issues in DNS Scanning {#context}

## Original NOTIFY for Zone Transfer Nudging

{{!RFC1996}} introduced the concept of a DNS Notify message which was used
to improve the convergence time for secondary servers when a DNS zone
had been updated in the primary. The basic idea was to augment the
traditional "pull" mechanism (a periodic SOA query) with a "push"
mechanism (a Notify) for a common case that was otherwise very
inefficient (due to either slow convergence or wasteful overly
frequent scanning of the primary for changes).

While it is possible to indicate how frequently checks should occur
(via the SOA Refresh parameter), these checks did not allow catching
zone changes that fall between checkpoints. {{!RFC1996}} addressed the
optimization of the time-and-cost trade-off between a secondary checking
frequently for new versions of a zone, and infrequent checking, by
replacing scheduled scanning with the more efficient NOTIFY mechanism.

## Similar Issues for DS Maintenance and Beyond

Today, we have similar issues with slow updates of DNS data in spite of
the data having been published. The two most obvious cases are CDS and
CSYNC scanners deployed in a growing number of TLD registries. Because of
the large number of child delegations, scanning for CDS and CSYNC records
is rather slow (as in infrequent).

It is only a very small number of the delegations that will have updated
CDS or CDNSKEY record in between two scanning runs. However, frequent
scanning for CDS and CDNSKEY records is costly, and infrequent scanning
causes slower convergence (i.e., delay until the DS RRset is updated).

Unlike in the original case, where the primary is able to suggest the
scanning interval via the SOA Refresh parameter, an equivalent mechanism
does not exist for DS-related scanning.

All of the above also applies to automated NS and glue record
maintenance via CSYNC scanning {{!RFC7477}}. Again, given that CSYNC
records change only rarely, frequent scanning of a large number of
delegations seems disproportionately costly, while infrequent scanning
causes slower convergence (delay until the delegation is updated).

While use of the NOTIFY mechanism for coordinating the key exchange in
multi-signer setups {{?I-D.ietf-dnsop-dnssec-automation}} is
conceivable, the detailed specification is left for future work.


# Change History (to be removed before publication)

* draft-ietf-dnsop-generalized-notify-08

- Nits from Dnsdir telechat review

* draft-ietf-dnsop-generalized-notify-07

> IESG review changes (notable: scheme now has mnemonic; else editorial)

> Nits from Opsdir telechat review

* draft-ietf-dnsop-generalized-notify-06

> Nits from Genart review

> Nits from Opsdir review

> Nits from Dnsdir review

* draft-ietf-dnsop-generalized-notify-05

> Editorial changes

* draft-ietf-dnsop-generalized-notify-04

> Add section on Implementation Status

> Use assigned DSYNC RRtype value

> Define DSYNC presentation format

> Make all needed IANA requests

> Editorial changes

* draft-ietf-dnsop-generalized-notify-03

> Include DNSSEC bootstrapping use case

> Remove sections with approaches not pursued

> Editorial changes

* draft-ietf-dnsop-generalized-notify-02

> Nits by Tim Wicinski

> Dnsdir feedback

> Specify timeout and error handling

> Editorial nits

> Reserve scheme value 0

* draft-ietf-dnsop-generalized-notify-01

> Reserve scheme values 128-255

> Rename NOTIFY rrtype to DSYNC (to distinguish from NOTIFY message)

> Describe endpoint discovery

> Discussion on garbage notifications

> More discussion on amplification risks

> Clean-up, editorial changes

* draft-ietf-dnsop-generalized-notify-00

> Revision after adoption.

* draft-thomassen-dnsop-generalized-dns-notify-02

> Add rationale for staying in band

> Add John as an author

* draft-thomassen-dnsop-generalized-dns-notify-01

> Mention Ry-to-Rr forwarding to accommodate RRR model

> Add port number flexibility

> Add scheme parameter

> Drop SRV-based alternative in favour of new NOTIFY RR

> Editorial improvements

* draft-thomassen-dnsop-generalized-dns-notify-00

> Initial public draft.
