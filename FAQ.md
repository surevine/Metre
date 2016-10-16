Metre FAQ
==========

Why not call it Meter?
-----

Metre is the right spelling. It's also the form typically used (even in US English) for poetry,
and XMPP often uses poetry terms (like stanza).

Who is "I"?
----

I am Dave Cridland. You can find me in various places. If you're using Metre, or interested in doing so,
please drop me a line, or an IM, or whatever.

Is this an XMPP server?
----

Well... Sort of. You can't connect clients to it, only servers and components (which are
sort of servers anyway). It can offer services - but it actually only provides XEP-0199
ping responses which are useful for diagnostics and testing. I might add version, eventually.

What it's for is for hosting components outside of a full server, and for letting two
servers which cannot, or must not, talk to each other directly connect through it "back to back".

So if you have a number of internal services which cannot be exposed, or cannot perform
the required security, you can have those setup as "forwarded" domains, and Metre will respond
to other, non-forwarded domains pretending to be them. As an example, if you want to expose
your service `example.com` to the world, but you don't want to risk having it directly accessible,
then you'd put Metre in your DMZ, have `example.com` connect to it, instead of the internet,
and then the world will connect to Metre.

Metre does need your TLS certificate and private key, however. It is acting as a "Man in
the middle", joining two security domains - the world (the outer domain) sees Metre as
being your XMPP Server, whereas your XMPP Server sees Metre as being, in effect, the world.

Example:

```xml
<remote>
  <domain name='example.com' forward='true'>
    <!-- Connect by low security: -->
    <transport type='s2s' sec='false'>
      <auth type='dialback'/>
    </transport>
    <ciphers>DEFAULT</ciphers>
    <dhparam size='1024'/>
    <!-- Use this X.509 identity -->
    <x509 chain='chain-file.pem' pkey='keyfile.pem'/>
  </domain>
  <any>
    <transport type='s2s'/>
  </any>
</remote>
```

How production-ready is this?
----

I would describe this as:

* MVP - it's not doing as much as I'd like, but it's essentially useful in its current form.
* Alpha - while it seems to work well enough for non-critical test deployments, production operational experience is lacking.

Does it score OK on the IM Observatory?
----

It can get an A without much effort; the defaults are designed around this. 

The defaults look complex!
----

Yes, they are - Metre tries to be smart about what defaults to use for a domain given
previous configuration. Loosely, if it's set to fetch status information (a global), it'll also
check it (a per-domain option).

Domains should inherit defaults from the `<any/>` domain, too.

If you're confused, check the config dump that'll be created in the data directory - it'll
contain all the configuration, including defaults, and is an accurate snapshot of the
running config (very useful for debugging and support!)

SIGHUP doesn't do a reload!
----

What Metre needs to do on a reload is flush all security information, disconnect all S2S
sessions and components that may have changed security parameters, and ensure that
all trust anchors on-disk are up to date.

Essentially, it may have to discard all runtime state. And figuring out exactly what runtime
state is safe to maintain, and therefore which sessions are safe to persist across this reload,
is fraught with danger of getting things wrong. So I've elected not to try - if you change the
configuration file, just restart - it really is much safer that way.

I'm connecting a Java server and...
----

Java, until recently, couldn't handle reasonable DH parameters used for Perfect
Forward Secrecy, and would choke.

Even now, you'll need to lower DH parameter sizes for that server - you can do this
with either `<dhparam size='1024'/>` or `<dhparam size='2048'/>` (for Java7 and Java8)
within the `<domain/>` stanza for the Java server. Metre picks the DH parameter size
based on the minimum of the requested, and the minimum configured size. Allowable
sizes are 1024, 2048 and 4096 - the latter is the default.

It may well be that the OpenSSL API used always asks for 1024 bits, mind...

Example:

```xml
  <domain name='tigase.example.com'>
    <dhparam size='1024'/>
  </domain>
```

My internal server only supports 3DES...
----

Just as with DH parameters, you can change the cipher suites as well for certain servers.

Just change the `<ciphers/>` directive to allow the ciphers you need. It's a traditional OpenSSL cipher list.

The default is (currently) HIGH:!3DES:!aNULL:!eNULL:@STRENGTH

Example:

```xml
  <domain name='ms-dos.example.com'>
    <ciphers>DEFAULT</ciphers><!-- Use OpenSSL defaults -->
  </domain>
```

I'm trying to connect to a domain hosted on Google, and ...
----

Google's broken GTalk service is largely unmaintained, and never supported any kind
of TLS. Metre requires TLS by default, but you can change that within the transport definition
by adding a `sec='false'` attribute to the transport. You'll almost certainly want to enable
dialback for these.

Example:

```xml
  <domain name='google.example.com'>
    <transport type='s2s' sec='false'><!-- Don't require a secure transport -->
     <auth type='dialback'/>
    </transport>
  </domain>
```

When does a config item get used?
----

Some are inbound, some are outbound, and some are confusing.

`<dhparam/>`, `<ciphers/>`, and `<transport/>` are all based on the remote server. So in the examples above,
google.example.com will be expected to be over S2S, with optional TLS, ms-dos.example.com will
have basic ciphers, and so on.

In particular, the authentication methods (pkix, dialback, and secret) are how Metre will
authenticate the remote domain, and not how it will authenticate itself *to* the remote domain.

Similarly, the `<dns/>` stanza controls lookups associated with the remote domain (so you can
override host lookups for just one domain, even if the host is also used by another).

However the `<x509/>` identity is how Metre will behave for the domain when it's acting as it locally, and not what it'll
be expecting when connecting remotely.

How are XEP-0114 components hosted?
----

XEP-0114 components are, to Metre, just another kind of remote server, albeit one it
cannot initiate a connection to. The difference is that you'll need to define the `<transport/>` type as "114",
and set a secret for the authentication with a child element of `<auth type='secret'/>`, containing the dialback secret, like so:

```xml
<domain name='component.example.com'>
  <transport type='114'>
     <auth type='secret'>S3Kr3T!</auth>
  </transport>
</domain>
```

Most component libraries will not negotiate TLS, so Metre will change the default for the `sec` attribute to false here,
but you can override it. Similarly, it will change the default for the `forward` attribute on the domain, since most people
will want components available to external servers - but you can change this if you want.

There's actually code present for connecting to another server as a component - if anyone would find that useful
let me know.

I use DNSSEC! What does Metre do?
----

That's great. Metre will:

* Throw away DNS records that are incorrectly [un]signed.
* Use DNSSEC-signed SRV records to gather more reference identifiers for certificates.
* You can also throw away all unsigned records for some server lookups.

To do the latter, add a `<dns dnssec='true'/>` element to the domain stanza (or any
stanza, if you're in an all-DNSSEC environment).

I want to override DNS / my peer doesn't do DNS properly.
----

You can override the SRV, A, and TLSA DNS lookups in the `<dns/>` element. Such overrides
are treated as if they were DNSSEC signed (since we assume your config file is a secure source),
so you can specify `dnssec='true'` if you override everything. Note that you'll need to override
both SRV and A records, typically.

```xml
<domain name='no-dns.example.com'>
  <dns>
    <srv host='xmpp-server.example.com' port='5269'/>
    <host name='xmpp-server.example.com' a='192.168.0.1'/>
  </dns>
</domain>
```

DNS overrides only affect those lookups performed for that domain. Loosely,
the internal API uses the remote domain as context for all lookups.

I hate CAs! Tell me it does DANE! Please, tell me it does DANE!
----

OK, than. It does DANE.

No, really, it does, but it's poorly tested, particularly for the DomainCert and
TrustAnchorAssertion. As a CA-hating person, therefore, you may be out of luck.

I suspect the CAConstraint and CertConstraint ones work OK.

It'll do both SubjectPublicKeyInfo and FullCert matching, but I've not tested hashes yet - though
they should work OK. (So matchtype='Full' is tested, but Sha256 and Sha512 aren't yet).

Note that there are an almost obscene number of permutations of DANE parameters and
potential inputs, so testing these will not be trivial.

I run a private CA internally and/or my partner organisation doesn't use a CA I recognise.
----

That's fine. Specifying a TLSA record override will work (subject to caveats above). TLSA
records overridden are always used, even if there isn't an (otherwise) secure DNS path
to them. The hostname/port are always ignored (long story, but it's safe), but still need
specifying (which is stupid, probably).

Match data can be given as either a filename (which must contain at least one '/') or as
base64 encoded data, for "Full" matchtype. The file (or data) must be a DER encoded object.

For the two hashes, you can just put the hash in hex form. Colons optional.

```xml
<domain name='shifty.example.com'>
  <dns>
    <tlsa hostname='shifty.example.com' port='5269' matchtype='Full' certusage='TrustAnchorAssertion' selector='FullCert'>./some-cert.der</tlsa>
  </dns>
</domain>
```

Does Metre pass through all traffic unchanged?
----

Currently, yes - although the outer stanza element itself is re-rendered.

However, this will change - it's intended to ultimately filter traffic and even respond
to some on behalf of internal servers.
