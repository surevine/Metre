/***

Copyright 2013-2016 Dave Cridland
Copyright 2014-2016 Surevine Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

***/

#include "config.h"

#include "spdlog/sinks/daily_file_sink.h"
#include "spdlog/sinks/stdout_sinks.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <fstream>
#include <random>
#include <algorithm>

#include <rapidxml.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#ifdef METRE_UNIX
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <WinSock2.h>
#include <WS2tcpip.h>
#endif
#include <dns.h>
#include <dhparams.h>
#include <router.h>
#include <unbound.h>
#include <sstream>
#include <base64.h>

#include "log.h"
#include <rapidxml_print.hpp>
#include <http.h>
#include <iomanip>
#if defined(HAVE_ICU) || defined(HAVE_ICU2)
#include <unicode/uidna.h>
#endif
#include <filter.h>
#include <cstring>
#include <unbound-event.h>

using namespace Metre;
using namespace rapidxml;

namespace {
#ifdef HAVE_ICU2
    std::string toASCII(std::string const &input) {
        if (std::find_if(input.begin(), input.end(), [](const char c) { return c & (1 << 7); }) == input.end())
            return input;
        static UIDNA *idna = 0;
        UErrorCode error = U_ZERO_ERROR;
        if (!idna) {
            idna = uidna_openUTS46(UIDNA_DEFAULT, &error);
        }
        std::string ret;
        ret.resize(1024);
        UIDNAInfo pInfo = UIDNA_INFO_INITIALIZER;
        auto sz = uidna_nameToASCII_UTF8(idna, input.data(), input.size(), const_cast<char *>(ret.data()), 1024, &pInfo,
                                         &error);
        ret.resize(sz);
        return ret;
    }
#else
#ifdef HAVE_ICUXX
    std::string toASCII(std::string const &input) {
        if (std::find_if(input.begin(), input.end(), [](const char c) { return c & (1 << 7); }) == input.end())
            return input;
        static UIDNA *idna = 0;
        UErrorCode error = U_ZERO_ERROR;
        if (!idna) {
            idna = uidna_openUTS46(UIDNA_DEFAULT, &error);
        }
        std::string ret;
        ret.resize(1024);
        UIDNAInfo pInfo = UIDNA_INFO_INITIALIZER;
        auto sz = uidna_nameToASCII_UTF8(idna, input.data(), input.size(), const_cast<char *>(ret.data()), 1024, &pInfo,
                                         &error);
        ret.resize(sz);
        return ret;
    }
#else

    std::string toASCII(std::string const &input) {
        if (std::find_if(input.begin(), input.end(), [](const char c) { return c & (1 << 7); }) == input.end()) {
            std::string ret = input;
            std::transform(ret.begin(), ret.end(), ret.begin(),
                           [](const char c) { return static_cast<char>(tolower(c)); });
            return ret;
        }
        throw std::runtime_error("IDNA domain but no ICU");
    }

#endif
#endif

    std::string const any_element = "any";
    std::string const xmlns = "http://surevine.com/xmlns/metre/config";
    std::string const root_name = "config";

    bool xmlbool(const char *val) {
        if (!val) return false;
        switch (val[0]) {
            case 't':
            case 'T':
            case 'y':
            case 'Y':
            case '1':
                return true;
        }
        return false;
    }

    bool xmlbool(xml_attribute<> const * attr) {
        if (attr && attr->value()) return xmlbool(attr->value());
        return false;
    }

    template<typename N>
    N attrval(xml_attribute<> const *attr) {
        if (!attr || !attr->value()) {
            throw std::runtime_error("Missing mandatory attribute");
        }
        std::istringstream ss(attr->value());
        N r;
        ss >> r;
        if (ss.eof()) {
            return r;
        }
        throw std::runtime_error("Mangled attribute");
    }

    template<typename N>
    N attrval(xml_attribute<> const *attr, N def) {
        if (!attr || !attr->value()) {
            return def;
        }
        std::istringstream ss(attr->value());
        N r;
        ss >> r;
        if (ss.eof()) {
            return r;
        }
        throw std::runtime_error("Mangled attribute");
    }

    template<>
    const char *attrval<const char *>(xml_attribute<> const *attr) {
        if (!attr || !attr->value()) {
            throw std::runtime_error("Missing mandatory attribute");
        }
        return attr->value();
    }

    template<>
    const char *attrval<const char *>(xml_attribute<> const *attr, const char *def) {
        if (!attr || !attr->value()) {
            return def;
        }
        return attr->value();
    }

    std::unique_ptr<Config::Domain> parse_domain(Config::Domain const *any, xml_node<> *domain, SESSION_TYPE def) {
        std::string name;
        bool forward = (def == INTERNAL || def == COMP);
        SESSION_TYPE sess = def;
        bool tls_required = !(def == INTERNAL || def == COMP);
        bool block = false;
        bool auth_pkix = (def == S2S) || (def == X2X);
        bool auth_dialback = false;
        bool dnssec_required = false;
        bool auth_pkix_crls = Config::config().fetch_pkix_status();
        bool auth_host = false;
        int stanza_timeout = 20;
        int connect_timeout = 10;
        std::string dhparam = "4096";
        std::string cipherlist = "HIGH:!3DES:!eNULL:!aNULL:@STRENGTH"; // Apparently 3DES qualifies for HIGH, but is 112 bits, which the IM Observatory marks down for.
        std::optional<std::string> auth_secret;
        if (any) {
            auth_pkix = any->auth_pkix();
            auth_dialback = any->auth_dialback();
            tls_required = tls_required && any->require_tls();
            dnssec_required = any->dnssec_required();
            dhparam = any->dhparam();
            cipherlist = any->cipherlist();
            auth_pkix_crls = any->auth_pkix_status();
            stanza_timeout = any->stanza_timeout();
            connect_timeout = any->connect_timeout();
        }
        if (any_element == domain->name()) {
            name = "";
        } else {
            auto name_a = domain->first_attribute("name");
            if (!name_a) {
                throw std::runtime_error("Missing name for domain element");
            }
            name = Jid(name_a->value()).domain(); // This stringpreps.
        }
        auto block_a = domain->first_attribute("block");
        if (block_a) {
            block = xmlbool(block_a->value());
        }
        auto transport = domain->first_node("transport");
        if (transport) {
            auto type_a = transport->first_attribute("type");
            if (type_a) {
                std::string type = type_a->value();
                if (type == "s2s") {
                    sess = S2S;
                } else if (type == "x2x") {
                    sess = X2X;
                } else if (type == "114") {
                    sess = COMP;
                    tls_required = false;
                    forward = true;
                } else if (type == "internal") {
                    sess = INTERNAL;
                    tls_required = true;
                    forward = true;
                } else {
                    throw std::runtime_error("Unknown transport type");
                }
            }
            auto tls_a = transport->first_attribute("sec");
            if (tls_a) {
                tls_required = xmlbool(tls_a->value());
            }
            stanza_timeout = attrval<int>(domain->first_attribute("stanza-timeout"), stanza_timeout);
            connect_timeout = attrval<int>(domain->first_attribute("connect-timeout"), connect_timeout);
            auto forward_a = domain->first_attribute("forward");
            if (forward_a) {
                forward = xmlbool(forward_a->value());
            }

            for (auto auth = transport->first_node("auth"); auth; auth = auth->next_sibling("auth")) {
                auto type_a = auth->first_attribute("type");
                if (type_a) {
                    std::string type = type_a->value();
                    if (type == "pkix") {
                        auth_pkix = true;
                        auto crl = auth->first_node("check-status");
                        if (crl && crl->value()) {
                            auth_pkix_crls = xmlbool(crl->value());
                            if (auth_pkix_crls && !Config::config().fetch_pkix_status())
                                throw std::runtime_error("Cannot check status without fetching status.");
                        }
                    } else if (type == "dialback") {
                        auth_dialback = true;
                    } else if (type == "secret") {
                        auth_secret.emplace(auth->value(), auth->value_size());
                    } else if (type == "host") {
                        auth_host = true;
                        if (sess == X2X) {
                            dnssec_required = true;
                        }
                    } else {
                        throw std::runtime_error("Unknown authentication type");
                    }
                }
            }
            if (!(block || auth_pkix || auth_dialback || auth_secret || auth_pkix)) {
                throw std::runtime_error("Cannot authenticate domain, but not blocked.");
            }
        }
        auto dom = std::make_unique<Config::Domain>(name, sess, forward, tls_required, block, auth_pkix, auth_dialback,
                                                    auth_host, std::move(auth_secret));
        dom->auth_pkix_status(auth_pkix_crls);
        dom->stanza_timeout(stanza_timeout);
        dom->connect_timeout(connect_timeout);
        auto x509t = domain->first_node("x509");
        if (x509t) {
            auto chain_a = x509t->first_attribute("chain");
            if (chain_a) {
                std::string chain = chain_a->value();
                auto pkey_a = x509t->first_attribute("pkey");
                if (pkey_a) {
                    std::string pkey = pkey_a->value();
                    dom->x509(chain, pkey);
                } else {
                    throw std::runtime_error("Missing pkey for x509");
                }
            } else {
                throw std::runtime_error("Missing chain for x509");
            }
        }
        auto dhparama = domain->first_node("dhparam");
        if (dhparama) {
            auto sza = dhparama->first_attribute("size");
            if (sza && sza->value()) dhparam = sza->value();
        }
        dom->dhparam(dhparam);
        auto ciphersa = domain->first_node("ciphers");
        if (ciphersa) {
            if (ciphersa->value()) cipherlist = ciphersa->value();
        }
        dom->cipherlist(cipherlist);
        auto dnst = domain->first_node("dns");
        if (dnst) {
            auto dnssec = dnst->first_attribute("dnssec");
            if (dnssec && dnssec->value()) {
                dnssec_required = xmlbool(dnssec->value());
            }
            for (auto hostt = dnst->first_node("host"); hostt; hostt = hostt->next_sibling("host")) {
                auto hosta = hostt->first_attribute("name");
                if (!hosta || !hosta->value()) throw std::runtime_error("Missing name in host DNS override");
                std::string host = hosta->value();
                auto aa = hostt->first_attribute("a");
                if (!aa || !aa->value()) throw std::runtime_error("Missing a in host DNS override");
                struct in_addr ina;
                if (inet_pton(AF_INET, aa->value(), &ina)) {
                    dom->host(host, ina.s_addr);
                }
            }
            for (auto srvt = dnst->first_node("srv"); srvt; srvt = srvt->next_sibling("srv")) {
                auto hosta = srvt->first_attribute("host");
                if (!hosta || !hosta->value()) throw std::runtime_error("Missing host in SRV DNS override");
                std::string host = hosta->value();
                auto tls = xmlbool(srvt->first_attribute("tls"));
                unsigned short port = attrval<unsigned short>(srvt->first_attribute("port"), tls ? 5270 : 5269);
                unsigned short weight = attrval<unsigned short>(srvt->first_attribute("weight"), 0);
                unsigned short prio = attrval<unsigned short>(srvt->first_attribute("priority"), 0);
                dom->srv(host, prio, weight, port, tls);
            }
            for (auto tlsa = dnst->first_node("tlsa"); tlsa; tlsa = tlsa->next_sibling("tlsa")) {
                auto hosta = tlsa->first_attribute("hostname");
                if (!hosta || !hosta->value()) throw std::runtime_error("Missing hostname in TLSA DNS override");
                std::string host = hosta->value();
                auto port = attrval<unsigned short>(tlsa->first_attribute("port"));
                auto certusagea = tlsa->first_attribute("certusage");
                if (!certusagea || !certusagea->value()) throw std::runtime_error("Missing certusage in TLSA DNS override");
                DNS::TlsaRR::CertUsage certUsage;
                std::string certusages = certusagea->value();
                if (certusages == "CAConstraint") {
                    certUsage = DNS::TlsaRR::CAConstraint;
                } else if (certusages == "CertConstraint") {
                    certUsage = DNS::TlsaRR::CertConstraint;
                } else if (certusages == "TrustAnchorAssertion") {
                    certUsage = DNS::TlsaRR::TrustAnchorAssertion;
                } else if (certusages == "DomainCert") {
                    certUsage = DNS::TlsaRR::DomainCert;
                } else {
                    throw std::runtime_error("Unknown certusage in TLSA DNS override");
                }
                auto matchtypea = tlsa->first_attribute("matchtype");
                DNS::TlsaRR::MatchType matchType = DNS::TlsaRR::Full;
                if (matchtypea && matchtypea->value()) {
                    std::string matchtypes = matchtypea->value();
                    if (matchtypes == "Full") {
                        matchType = DNS::TlsaRR::Full;
                    } else if (matchtypes == "Sha256") {
                        matchType = DNS::TlsaRR::Sha256;
                    } else if (matchtypes == "Sha512") {
                        matchType = DNS::TlsaRR::Sha512;
                    } else {
                        throw std::runtime_error("Unknown matchtype in TLSA DNS override");
                    }
                }
                auto selectora = tlsa->first_attribute("selector");
                DNS::TlsaRR::Selector selector = DNS::TlsaRR::FullCert;
                if (selectora && selectora->value()) {
                    std::string sel = selectora->value();
                    if (sel == "FullCert") {
                        selector = DNS::TlsaRR::FullCert;
                    } else if (sel == "SubjectPublicKeyInfo") {
                        selector = DNS::TlsaRR::SubjectPublicKeyInfo;
                    } else {
                        throw std::runtime_error("Unknown selector in TLSA DNS override");
                    }
                }
                dom->tlsa(host, port, certUsage, selector, matchType, tlsa->value());
            }
        }
        dom->dnssec_required(dnssec_required);
        auto filter_in = domain->first_node("filter-in");
        if (filter_in) {
            for (auto filter = filter_in->first_node(); filter; filter = filter->next_sibling()) {
                if (filter->type() != node_element) continue;
                std::string filter_name{filter->name(), filter->name_size()};
                auto it = Filter::all_filters().find(filter_name);
                if (it == Filter::all_filters().end()) {
                    throw std::runtime_error("Unknown filter " + filter_name);
                }
                auto &filter_desc = (*it).second;
                dom->filters().emplace_back(filter_desc->create(*dom, filter));
            }
        }
        return dom;
    }

    Config *s_config = nullptr;

    bool openssl_init = false;
}

Config::Domain::Domain(std::string const &domain, SESSION_TYPE transport_type, bool forward, bool require_tls,
                       bool block, bool auth_pkix, bool auth_dialback, bool auth_host,
                       std::optional<std::string> &&auth_secret)
        : m_domain(domain), m_type(transport_type), m_forward(forward), m_require_tls(require_tls), m_block(block),
          m_auth_pkix(auth_pkix), m_auth_dialback(auth_dialback), m_auth_host(auth_host), m_auth_secret(auth_secret),
          m_ssl_ctx(nullptr) {
}

Config::Domain::Domain(Config::Domain const &any, std::string const &domain)
        : m_domain(domain), m_type(any.m_type), m_forward(any.m_forward), m_require_tls(any.m_require_tls),
          m_block(any.m_block), m_auth_pkix(any.m_auth_pkix), m_auth_crls(any.m_auth_crls),
          m_auth_dialback(any.m_auth_dialback), m_auth_host(any.m_auth_host), m_dnssec_required(any.m_dnssec_required),
          m_stanza_timeout(any.m_stanza_timeout), m_dhparam(any.m_dhparam), m_cipherlist(any.m_cipherlist),
          m_ssl_ctx(nullptr), m_parent(&any) {
}

FILTER_RESULT Config::Domain::filter(SESSION_DIRECTION dir, Stanza &s) const {
    rapidxml::xml_node<> const *node = s.node();
    if (!node) {
        // Synthetic Stanza. Probably a bounce, or similar.
        return PASS;
    }
    for (auto &filter : m_filters) {
        if (filter->apply(dir, s) == DROP) return DROP;
    }
    return PASS;
}



Config::Domain::~Domain() {
    if (m_ssl_ctx) {
        SSL_CTX_free(m_ssl_ctx);
        m_ssl_ctx = nullptr;
    }
}

void Config::Domain::host(std::string const &ihostname, uint32_t inaddr) {
    auto address = std::make_unique<DNS::Address>();
    std::string hostname = toASCII(ihostname);
    if (hostname[hostname.length() - 1] != '.') hostname += '.';
    address->dnssec = true;
    address->hostname = hostname;
    address->addr.emplace_back();
    struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&*address->addr.rbegin());
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inaddr;
    m_host_arecs[hostname] = std::move(address);
}

int Config::verify_callback_cb(int preverify_ok, struct x509_store_ctx_st *st) {
    if (!preverify_ok) {
        const int name_sz = 256;
        std::string cert_name;
        cert_name.resize(name_sz);
        X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(st)),
                          const_cast<char *>(cert_name.data()), name_sz);
        cert_name.resize(cert_name.find('\0'));
        Config::config().m_logger->info("Cert failed basic verification: {}", cert_name);
        Config::config().m_logger->info("Error is {}", X509_verify_cert_error_string(X509_STORE_CTX_get_error(st)));
    } else {
        const int name_sz = 256;
        std::string cert_name;
        cert_name.resize(name_sz);
        X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(st)),
                          const_cast<char *>(cert_name.data()), name_sz);
        cert_name.resize(cert_name.find('\0'));
        Config::config().m_logger->debug("Cert passed basic verification: {}", cert_name);
        if (Config::config().m_fetch_crls) {
            auto cert = X509_STORE_CTX_get_current_cert(st);
            std::unique_ptr<STACK_OF(DIST_POINT),std::function<void(STACK_OF(DIST_POINT) *)>> crldp_ptr{(STACK_OF(DIST_POINT)*)X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL),[](STACK_OF(DIST_POINT) * crldp){ sk_DIST_POINT_pop_free(crldp, DIST_POINT_free); }};
            auto crldp = crldp_ptr.get();
            if (crldp) {
                for (int i = 0; i != sk_DIST_POINT_num(crldp); ++i) {
                    DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
                    if (dp->distpoint->type == 0) { // Full Name
                        auto names = dp->distpoint->name.fullname;
                        for (int ii = 0; ii != sk_GENERAL_NAME_num(names); ++ii) {
                            GENERAL_NAME *name = sk_GENERAL_NAME_value(names, ii);
                            if (name->type == GEN_URI) {
                                ASN1_IA5STRING *uri = name->d.uniformResourceIdentifier;
                                std::string uristr{reinterpret_cast<char *>(uri->data),
                                                   static_cast<std::size_t>(uri->length)};
                                Config::config().m_logger->info("Prefetching CRL for {} - {}", cert_name, uristr);
                                Http::crl(uristr);
                            }
                        }
                    }
                }
            }
        }
    }
    return 1;
}

namespace {
    int ssl_servername_cb(SSL *ssl, int *ad, void *arg) {
        const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (!servername) return SSL_TLSEXT_ERR_OK;
        SSL_CTX *old_ctx = SSL_get_SSL_CTX(ssl);
        SSL_CTX *new_ctx = Config::config().domain(Jid(servername).domain()).ssl_ctx();
        if (!new_ctx) new_ctx = Config::config().domain("").ssl_ctx();
        if (new_ctx != old_ctx) SSL_set_SSL_CTX(ssl, new_ctx);
        return SSL_TLSEXT_ERR_OK;
    }
}

void Config::Domain::x509(std::string const &chain, std::string const &pkey) {
    if (!openssl_init) {
        SSL_library_init();
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        if (RAND_poll() == 0) {
            throw std::runtime_error("OpenSSL init failed");
        }
        openssl_init = true;
    }
    if (m_ssl_ctx) {
        SSL_CTX_free(m_ssl_ctx);
        m_ssl_ctx = nullptr;
    }
    m_ssl_ctx = SSL_CTX_new(SSLv23_method());
    SSL_CTX_set_options(m_ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_ALL);
    SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, Config::verify_callback_cb);
    if (SSL_CTX_use_certificate_chain_file(m_ssl_ctx, chain.c_str()) != 1) {
        for (unsigned long e = ERR_get_error(); e != 0; e = ERR_get_error()) {
            Config::config().logger().error("OpenSSL Error: {}", ERR_reason_error_string(e));
        }
        throw std::runtime_error("Couldn't load chain file");
    }
    if (SSL_CTX_use_PrivateKey_file(m_ssl_ctx, pkey.c_str(), SSL_FILETYPE_PEM) != 1) {
        for (unsigned long e = ERR_get_error(); e != 0; e = ERR_get_error()) {
            Config::config().logger().error("OpenSSL Error: {}", ERR_reason_error_string(e));
        }
        throw std::runtime_error("Couldn't load keyfile");
    }
    if (SSL_CTX_check_private_key(m_ssl_ctx) != 1) {
        for (unsigned long e = ERR_get_error(); e != 0; e = ERR_get_error()) {
            Config::config().logger().error("OpenSSL Error: {}", ERR_reason_error_string(e));
        }
        throw std::runtime_error("Private key mismatch");
    }
    SSL_CTX_set_purpose(m_ssl_ctx, X509_PURPOSE_SSL_SERVER);
    SSL_CTX_set_default_verify_paths(m_ssl_ctx);
    SSL_CTX_set_tlsext_servername_callback(m_ssl_ctx, ssl_servername_cb);
    std::string ctx = "Metre::" + m_domain;
    SSL_CTX_set_session_id_context(m_ssl_ctx, reinterpret_cast<const unsigned char *>(ctx.c_str()),
                                   static_cast<unsigned int>(ctx.size()));
}

SSL_CTX *Config::Domain::ssl_ctx() const {
    SSL_CTX *ctx = m_ssl_ctx;
    if (!ctx) {
        for (Domain const *d = this; d; d = d->m_parent) {
            ctx = d->m_ssl_ctx;
            if (ctx) break;
        }
    }
    return ctx;
}

Config::Config(std::string const &filename) : m_config_str(), m_dialback_secret(random_identifier()) {
    s_config = this;
    // Spin up a temporary error logger.
    m_root_logger = spdlog::stderr_color_st("console");
    spdlog::set_level(spdlog::level::trace);
    //spdlog::set_sync_mode();
    load(filename);
    std::string tmp = asString();
    std::ofstream of(m_data_dir + "/" + "metre.running.xml", std::ios_base::trunc);
    of << tmp;
    m_ub_ctx = ub_ctx_create();
    if (!m_ub_ctx) {
        throw std::runtime_error("DNS context creation failure.");
    }
}

Config::~Config() {
    // TODO: Should really do this, but need to shut it down first: ub_ctx_delete(m_ub_ctx);
}

void Config::load(std::string const &filename) {
    std::ifstream file(filename);
    std::string str{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    m_config_str = std::move(str);
    rapidxml::xml_document<> doc;
    doc.parse<parse_full>(const_cast<char *>(m_config_str.c_str()));
    auto root_node = doc.first_node();
    if (xmlns != root_node->xmlns()) {
        throw std::runtime_error("Wrong namespace for config");
    }
    if (root_name != root_node->name()) {
        throw std::runtime_error("Wrong name for config");
    }
    auto globals = root_node->first_node("globals");
    if (globals) {
        auto default_domain = globals->first_node("domain");
        if (default_domain) {
            auto name_a = default_domain->first_attribute("name");
            if (name_a) {
                m_default_domain = name_a->value();
            }
        }
        auto rundir = globals->first_node("rundir");
        if (rundir && rundir->value()) {
            m_runtime_dir = rundir->value();
        }
        auto logfile = globals->first_node("logfile");
        if (logfile && logfile->value()) {
            m_logfile = logfile->value();
        }
        auto bootm = globals->first_node("boot_method");
        if (bootm && bootm->value()) {
            m_boot = bootm->value();
        }
        auto datadir = globals->first_node("datadir");
        if (datadir && datadir->value()) {
            m_data_dir = datadir->value();
        }
        auto dns_keys = globals->first_node("dnssec");
        if (dns_keys && dns_keys->value()) {
            m_dns_keys = dns_keys->value();
        }
        auto crls = globals->first_node("fetch-crls");
        if (crls && crls->value()) {
            m_fetch_crls = xmlbool(crls->value());
        }
        auto filters = globals->first_node("filter");
        if (filters) {
            for (auto filter = filters->first_node(); filter; filter = filter->next_sibling()) {
                if (filter->type() != node_element) continue;
                std::string filter_name{filter->name(), filter->name_size()};
                auto it = Filter::all_filters().find(filter_name);
                if (it == Filter::all_filters().end()) {
                    throw std::runtime_error("Unknown filter " + filter_name);
                }
                auto &filter_desc = (*it).second;
                filter_desc->config(filter);
            }
        }
    }
    if (m_runtime_dir.empty()) {
        m_runtime_dir = "/var/run/";
    }
    if (m_data_dir.empty()) {
        m_data_dir = m_runtime_dir;
    }
    m_pidfile = m_runtime_dir + "/metre.pid";
    if (m_boot.empty()) {
        m_boot = "none";
    }
    Config::Domain *any_domain = nullptr;
    auto external = root_node->first_node("remote");
    if (external) {
        auto any = external->first_node("any");
        if (any) {
            std::unique_ptr<Config::Domain> dom = parse_domain(nullptr, any, S2S);
            any_domain = &*dom; // Save this pointer.
            m_domains[dom->domain()] = std::move(dom);
        } else {
            m_domains[""] = std::make_unique<Config::Domain>("", INTERNAL, false, true, true, true, true, false,
                                                             std::optional<std::string>());
        }
        for (auto domain = external->first_node("domain"); domain; domain = domain->next_sibling("domain")) {
            std::unique_ptr<Config::Domain> dom = parse_domain(any_domain, domain, S2S);
            m_domains[dom->domain()] = std::move(dom);
        }
    }
    auto internal = root_node->first_node("local");
    if (internal) {
        for (auto domain = internal->first_node("domain"); domain; domain = domain->next_sibling("domain")) {
            std::unique_ptr<Config::Domain> dom = parse_domain(any_domain, domain, INTERNAL);
            m_domains[dom->domain()] = std::move(dom);
        }
    }
    auto listeners = root_node->first_node("listeners");
    if (listeners) {
        for (auto listener = listeners->first_node("listener"); listener; listener = listener->next_sibling(
                "listener")) {
            // address : port* : default_domain[*X2X] : session_type : tls_mode
            auto port = attrval<unsigned short>(listener->first_attribute("port"));
            SESSION_TYPE stype = S2S;
            TLS_MODE tls = xmlbool(listener->first_attribute("tls")) ? IMMEDIATE : STARTTLS;
            auto stypea = listener->first_attribute("type");
            if (stypea && stypea->value()) {
                std::string s = stypea->value();
                if (s == "s2s") {
                    stype = S2S;
                } else if (s == "x2x") {
                    stype = X2X;
                } else if (s == "114") {
                    stype = COMP;
                } else {
                    throw std::runtime_error("Unknown type for listener");
                }
            }
            auto local_domain = attrval<const char *>(listener->first_attribute("local-domain"), "");
            auto remote_domain = attrval<const char *>(listener->first_attribute("remote-domain"), "");
            auto address = attrval<const char *>(listener->first_attribute("address"), "::");
            std::ostringstream ss;
            ss << "unnamed-" << address << "-" << port;
            auto name = attrval<const char *>(listener->first_attribute("name"), ss.str().c_str());
            m_listeners.emplace_back(local_domain, remote_domain, name, address, port, tls, stype);
            if (remote_domain[0]) m_listeners.rbegin()->allowed_domains.emplace(remote_domain);
            for (auto allowed = listener->first_node("allowed-domain"); allowed; allowed = allowed->next_sibling(
                    "allowed-domain")) {
                if (!allowed->value()) throw std::runtime_error("Empty allowed-domain");
                m_listeners.rbegin()->allowed_domains.emplace(allowed->value());
            }
        }
    } else {
        m_listeners.emplace_back("", "", "S2S", "::", 5269, STARTTLS, S2S);
        m_listeners.emplace_back("", "", "XEP-0368", "::", 5270, IMMEDIATE, S2S);
    }
}

Config::Listener::Listener(std::string const &ldomain, std::string const &rdomain, std::string const &aname,
                           const char *address, unsigned short port, TLS_MODE atls,
                           SESSION_TYPE asess)
        : session_type(asess), tls_mode(atls), name(aname), local_domain(ldomain), remote_domain(rdomain) {
    std::memset(&m_sockaddr, 0, sizeof(m_sockaddr)); // Clear, to avoid valgrind complaints later.
    if (1 == inet_pton(AF_INET6, address, &(reinterpret_cast<struct sockaddr_in6 *>(&m_sockaddr)->sin6_addr))) {
        struct sockaddr_in6 *sa = reinterpret_cast<struct sockaddr_in6 *>(&m_sockaddr);
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(port);
    } else if (1 == inet_pton(AF_INET, address, &(reinterpret_cast<struct sockaddr_in *>(&m_sockaddr)->sin_addr))) {
        struct sockaddr_in *sa = reinterpret_cast<struct sockaddr_in *>(&m_sockaddr);
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
    } else {
        throw std::runtime_error("Couldn't understand address syntax " + std::string(address));
    }
    if (asess == X2X) {
        if (local_domain.empty() || remote_domain.empty()) {
            throw std::runtime_error("Missing local or remote domains");
        }
    }
}

std::string Config::asString() {
    xml_document<> doc;
    auto root = doc.allocate_node(node_element, root_name.c_str());
    root->append_attribute(doc.allocate_attribute("xmlns", xmlns.c_str()));
    auto alloc_short = [&doc](long x) {
        std::ostringstream ss;
        ss << x;
        return doc.allocate_string(ss.str().data());
    };
    {
        root->append_node(doc.allocate_node(node_data, nullptr, "\n"));
        auto globals = doc.allocate_node(node_element, "globals");

        {
            if (m_default_domain.empty()) {
                globals->append_node(
                        doc.allocate_node(node_comment, nullptr, "<domain name='default.domain.example'/>"));
            } else {
                auto domain = doc.allocate_node(node_element, "domain");
                domain->append_attribute(doc.allocate_attribute("name", m_default_domain.c_str()));
                globals->append_node(domain);
            }
            globals->append_node(doc.allocate_node(node_comment, nullptr,
                                                   "Default domain. Used in extremis if no domain is present in the stream header."));
            globals->append_node(doc.allocate_node(node_data, nullptr, "\n"));
        }

        auto global = [&] (const char * elname, std::string const & val, const char * comment) {
            globals->append_node(doc.allocate_node(node_element, elname, doc.allocate_string(val.c_str())));
            globals->append_node(doc.allocate_node(node_comment, nullptr, comment));
            globals->append_node(doc.allocate_node(node_data, nullptr, "\n"));
        };

        global("rundir", m_runtime_dir, "Runtime directory, used to store pid file.");
        global("datadir", m_data_dir, "Data directory, used only for the running config.");
        global("logfile", m_logfile, "Logfile path.");
        global("dnssec", m_dns_keys, "DNSSEC root keys file.");
        global("boot_method", m_boot, "Boot method - none, fork, or systemd");
        global("fetch-crls", m_fetch_crls ? "true" : "false",
               "Controls if CRLs are fetched - MUST be on for status checking!");
        global("dnssec", m_dns_keys, "DNS key file - obtain this from IANA");

        xml_node<> *filters = doc.allocate_node(node_element, "filter");
        filters->append_node(
                doc.allocate_node(node_comment, nullptr, "Filter global configuration for all compiled-in filters"));
        for (auto const &filter : Filter::all_filters()) {
            auto filter_conf = filter.second->config(doc);
            filters->append_node(filter_conf);
        }
        globals->append_node(filters);

        root->append_node(globals);
    }
    {
        root->append_node(doc.allocate_node(node_data, nullptr, "\n"));
        auto domains = doc.allocate_node(node_element, "remote");
        domains->append_node(doc.allocate_node(node_comment, nullptr, "All domains, internal and external, are listed here.\nNote that this will include all settings, including defaults.\n"));
        domains->append_node(doc.allocate_node(node_data, nullptr, "\n"));

        auto dout = [&](Config::Domain const & dom) {
            auto d = doc.allocate_node(node_element, dom.domain().empty() ? "any" : "domain");
            if (!dom.domain().empty()) {
                d->append_attribute(doc.allocate_attribute("name", dom.domain().c_str()));
                d->append_attribute(doc.allocate_attribute("forward", dom.forward() ? "true" : "false"));
                d->append_attribute(doc.allocate_attribute("stanza-timeout", alloc_short(dom.stanza_timeout())));
                d->append_node(doc.allocate_node(node_comment, nullptr, "A remote domain. Forwarded domains are proxied through to non-forwarded domains."));
                d->append_node(doc.allocate_node(node_comment, nullptr,
                                                 "A 'sec' attribute set to true mandates a secured connection (usually TLS)."));
            }
            {
                auto transport = doc.allocate_node(node_element, "transport");
                const char *tt;
                switch (dom.transport_type()) {
                    case INTERNAL:
                        tt = "internal";
                        break;
                    case S2S:
                        tt = "s2s";
                        break;
                    case COMP:
                        tt = "114";
                        break;
                    default:
                        return;
                }
                transport->append_attribute(doc.allocate_attribute("type", tt));
                transport->append_attribute(doc.allocate_attribute("sec", dom.require_tls() ? "true" : "false"));
                transport->append_attribute(
                        doc.allocate_attribute("connect-timeout", alloc_short(dom.connect_timeout())));
                if (dom.auth_pkix()) {
                    auto auth = doc.allocate_node(node_element, "auth");
                    auth->append_attribute(doc.allocate_attribute("type", "pkix"));
                    auth->append_node(
                            doc.allocate_node(node_element, "check-status", dom.m_auth_crls ? "true" : "false"));
                    transport->append_node(auth);
                }
                if (dom.auth_dialback()) {
                    auto auth = doc.allocate_node(node_element, "auth");
                    auth->append_attribute(doc.allocate_attribute("type", "dialback"));
                    transport->append_node(auth);
                }
                if (dom.auth_secret()) {
                    auto auth = doc.allocate_node(node_element, "auth", dom.auth_secret()->c_str());
                    auth->append_attribute(doc.allocate_attribute("type", "secret"));
                    transport->append_node(auth);
                }
                d->append_node(transport);
            }
            {
                auto dns = doc.allocate_node(node_element, "dns");
                dns->append_attribute(doc.allocate_attribute("dnssec", dom.dnssec_required() ? "true" : "false"));
                dns->append_node(
                        doc.allocate_node(node_comment, nullptr,
                                          "DNS overrides are always treated as if signed with DNSSEC."));
                if (dom.m_srvrec) {
                    auto &srv = dom.m_srvrec;
                    for (auto &rr : srv->rrs) {
                        auto s = doc.allocate_node(node_element, "srv");
                        s->append_attribute(doc.allocate_attribute("host", rr.hostname.c_str()));
                        s->append_attribute(doc.allocate_attribute("port", alloc_short(rr.port)));
                        s->append_attribute(doc.allocate_attribute("priority", alloc_short(rr.priority)));
                        s->append_attribute(doc.allocate_attribute("weight", alloc_short(rr.weight)));
                        s->append_attribute(doc.allocate_attribute("tls", rr.tls ? "true" : "false"));
                        dns->append_node(s);
                    }
                }
                dns->append_node(doc.allocate_node(node_comment, nullptr,
                                                   "<srv host='hostname to connect to' port='port number' priority='prio' weight='weight' tls='bool'/>"));
                dns->append_node(doc.allocate_node(node_comment, nullptr, "Most values (not hostname) default sensibly - but note that priority and weight default to zero, which is unusuable if multiple records are used."));
                for (auto & tlsa : dom.tlsa()) {
                    for (auto &rr : tlsa.rrs) {
                        std::stringstream ss(tlsa.domain);
                        unsigned short int port = 0;
                        std::string hostname;
                        char underscore;
                        ss >> underscore >> port >> hostname;
                        auto e = doc.allocate_node(node_element, "tlsa");
                        e->append_attribute(
                                doc.allocate_attribute("hostname", doc.allocate_string(hostname.c_str() + 6)));
                        e->append_attribute(doc.allocate_attribute("port", alloc_short(port)));
                        const char *match;
                        switch (rr.matchType) {
                            case DNS::TlsaRR::Full:
                            default:
                                match = "Full";
                                break;
                            case DNS::TlsaRR::Sha256:
                                match = "Sha256";
                                break;
                            case DNS::TlsaRR::Sha512:
                                match = "Sha512";
                                break;
                        }
                        e->append_attribute(doc.allocate_attribute("matchtype", match));
                        const char *selector;
                        switch (rr.selector) {
                            case DNS::TlsaRR::FullCert:
                            default:
                                selector = "FullCert";
                                break;
                            case DNS::TlsaRR::SubjectPublicKeyInfo:
                                selector = "SubjectPublicKeyInfo";
                                break;
                        }
                        e->append_attribute(doc.allocate_attribute("selector", selector));
                        const char *certUsage;
                        switch (rr.certUsage) {
                            case DNS::TlsaRR::CAConstraint:
                                certUsage = "CAConstraint";
                                break;
                            case DNS::TlsaRR::CertConstraint:
                                certUsage = "CertConstraint";
                                break;
                            case DNS::TlsaRR::DomainCert:
                            default:
                                certUsage = "DomainCert";
                                break;
                            case DNS::TlsaRR::TrustAnchorAssertion:
                                certUsage = "TrustAnchorAssertion";
                                break;
                        }
                        e->append_attribute(doc.allocate_attribute("certusage", certUsage));
                        if (rr.matchType == DNS::TlsaRR::Full) {
                            // Base64 data (it might have come from a file, but never mind).
                            e->value(doc.allocate_string(base64_encode(rr.matchData).c_str()));
                        } else {
                            std::ostringstream os;
                            os << std::hex << std::setfill('0') << std::setw(2);
                            bool colon = false;
                            for (char c : rr.matchData) {
                                auto byte = static_cast<unsigned short>(c);
                                // Use numeric type to avoid treating as character.
                                if (!colon) {
                                    colon = true;
                                } else {
                                    os << ':';
                                }
                                os << byte;
                            }
                            e->value(doc.allocate_string(os.str().c_str()));
                        }
                        dns->append_node(e);
                    }
                }
                dns->append_node(doc.allocate_node(node_comment, nullptr,
                                                   "<tlsa host='nominal hostname [ignored]' port='nominal port number [ignored]' certusage='CAConstraint|CertConstraint|DomainCert|TrustAnchorAssertion' selector='FullCert|SubjectPublicKeyInfo' matchtype='Full|Sha256|Sha512'>Value</tsla>"));
                dns->append_node(doc.allocate_node(node_comment, nullptr,
                                                   "Value should be hex hash for hash matchtypes, or a filename (no return character, at least one '/') or base64 DER (PEM without headers)"));
                for (auto const &h : dom.m_host_arecs) {
                    auto host = doc.allocate_node(node_element, "host");
                    host->append_attribute(doc.allocate_attribute("name", h.first.c_str()));
                    char buf[32];
                    struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(h.second->addr.data());
                    inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
                    host->append_attribute(doc.allocate_attribute("a", doc.allocate_string(buf)));
                    dns->append_node(host);
                }
                dns->append_node(
                        doc.allocate_node(node_comment, nullptr, "<host name='name.example' a='123.45.67.89'/>"));
                d->append_node(dns);
            }
            {
                SSL_CTX *ctx = dom.ssl_ctx();
                if (!ctx) {
                    ctx = domain("").ssl_ctx();
                }
                if (ctx) {
                    auto x509 = doc.allocate_node(node_element, "x509");
                    std::string prefix;
                    if (dom.domain().empty()) {
                        prefix = "any_";
                    } else {
                        prefix = dom.domain() + "_";
                    }
                    STACK_OF(X509) *chain = nullptr;
                    std::string chainfile = m_data_dir + "/" + prefix + "chain.pem";
                    if (0 == SSL_CTX_get0_chain_certs(ctx, &chain) && chain) {
                        FILE *fp = fopen(chainfile.c_str(), "w");
                        for (int i = 0; i < sk_X509_num(chain); ++i) {
                            X509 *item = sk_X509_value(chain, i);
                            PEM_write_X509(fp, item);
                        }
                        fclose(fp);
                        x509->append_attribute(doc.allocate_attribute("chain", doc.allocate_string(chainfile.c_str())));
                    }
                    std::string keyfile = m_data_dir + "/" + prefix + "key.pem";
                    bool key_okay = false;
                    if (SSL_CTX_get0_privatekey(ctx)) {
                        FILE *fp = fopen(keyfile.c_str(), "w");
                        PEM_write_PKCS8PrivateKey(fp, SSL_CTX_get0_privatekey(ctx), nullptr, nullptr, 0,
                                                  nullptr,
                                                  nullptr);
                        fclose(fp);
                        x509->append_attribute(doc.allocate_attribute("pkey", doc.allocate_string(keyfile.c_str())));
                        key_okay = true;
                    }
                    if (key_okay || chain) {
                        d->append_node(x509);
                    }
                }
                d->append_node(doc.allocate_node(node_comment, nullptr, "The x509 element provides a chainfile and private key to use as the local identity when acting as this domain."));
            }
            {
                auto dhp = doc.allocate_node(node_element, "dhparam");
                dhp->append_attribute(doc.allocate_attribute("size", dom.dhparam().c_str()));
                d->append_node(dhp);
                d->append_node(doc.allocate_node(node_comment, nullptr, "Provides the size of the DH keys used for Perfect Forward Secrecy - 1024, 2048, or 4096."));
            }
            d->append_node(doc.allocate_node(node_element, "ciphers", dom.cipherlist().c_str()));
            d->append_node(doc.allocate_node(node_comment, nullptr, "This is a normal OpenSSL cipher string."));
            {
                auto filter_in = doc.allocate_node(node_element, "filter-in");
                filter_in->append_node(doc.allocate_node(node_comment, nullptr,
                                                         "Config for any filters active for inbound stanzas to this domain"));
                for (auto const &filter : dom.m_filters) {
                    filter_in->append_node(filter->dump_config(doc));
                }
                d->append_node(filter_in);
            }
            domains->append_node(d);
        };
        for (auto & p : m_domains) {
            dout(*(p.second));
        }
        root->append_node(domains);
        {
            // Listeners
            auto listeners = doc.allocate_node(node_element, "listeners");
            for (auto &listen : m_listeners) {
                auto listener = doc.allocate_node(node_element, "listener");
                if (!listen.local_domain.empty())
                    listener->append_attribute(doc.allocate_attribute("local-domain", listen.local_domain.c_str()));
                if (!listen.remote_domain.empty())
                    listener->append_attribute(doc.allocate_attribute("remote-domain", listen.remote_domain.c_str()));
                listener->append_attribute(doc.allocate_attribute("name", listen.name.c_str()));
                if (listen.sockaddr()->sa_family == AF_INET) {
                    const struct sockaddr_in *sa = reinterpret_cast<const struct sockaddr_in *>(listen.sockaddr());
                    char buf[1024];
                    inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(struct sockaddr_in));
                    listener->append_attribute(doc.allocate_attribute("address", doc.allocate_string(buf)));
                    listener->append_attribute(doc.allocate_attribute("port", alloc_short(ntohs(sa->sin_port))));
                } else if (listen.sockaddr()->sa_family == AF_INET6) {
                    const struct sockaddr_in6 *sa = reinterpret_cast<const struct sockaddr_in6 *>(listen.sockaddr());
                    char buf[1024];
                    inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof(struct sockaddr_in6));
                    listener->append_attribute(doc.allocate_attribute("address", doc.allocate_string(buf)));
                    listener->append_attribute(doc.allocate_attribute("port", alloc_short(ntohs(sa->sin6_port))));
                }
                const char *stype = "s2s";
                switch (listen.session_type) {
                    case S2S:
                        stype = "s2s";
                        break;
                    case X2X:
                        stype = "x2x";
                        break;
                    case COMP:
                        stype = "114";
                        break;
                    default:
                        continue;
                };
                listener->append_attribute(doc.allocate_attribute("type", stype));
                listener->append_attribute(
                        doc.allocate_attribute("tls", listen.tls_mode == IMMEDIATE ? "true" : "false"));
                listeners->append_node(listener);
            }
            root->append_node(listeners);
        }
    }
    doc.append_node(root);
    std::string tmp;
    rapidxml::print(std::back_inserter(tmp), doc);
    return tmp;
}

void Config::log_init(bool systemd) {
    if (!systemd && m_logfile.empty()) {
        m_logfile = "/var/log/metre/metre.log";
    }
    // Initialize logging.
    if (!m_logfile.empty()) {
        m_root_logger = spdlog::daily_logger_st("global", m_logfile);
    } else {
        m_root_logger = spdlog::stderr_logger_st("global");
    }
    m_root_logger->flush_on(spdlog::level::trace);
    m_root_logger->set_level(spdlog::level::trace);
    m_logger = logger("config");
}

Config::Domain const &Config::domain(std::string const &dom) const {
    std::string search{dom};
    auto it = m_domains.find(dom);
    while (it == m_domains.end()) {
        it = m_domains.find("*." + search);
        if (it == m_domains.end()) {
            auto dot = search.find('.');
            if (dot == std::string::npos) {
                search = "";
            } else {
                search = search.substr(dot + 1);
            }
            it = m_domains.find(search);
        }
        if (it == m_domains.end()) {
            assert(search != "");
            continue;
        }
        m_logger->info("Creating new domain config {}from parent ({})", dom, (*it).second->domain());
        std::unique_ptr<Config::Domain> newdom{new Config::Domain(*(*it).second, dom)};
        std::tie(it, std::ignore) = const_cast<Config *>(this)->m_domains.insert(
                std::make_pair(dom, std::move(newdom)));
        break;
    }
    return *(*it).second;
}

std::string Config::random_identifier() const {
    const size_t id_len = 16;
    char characters[] = "0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ@";
    std::default_random_engine random(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(characters) - 2);
    std::string id(id_len, char{});
    std::generate_n(id.begin(), id_len, [&characters, &random, &dist]() { return characters[dist(random)]; });
    return id;
}

std::string Config::dialback_key(std::string const &id, std::string const &local_domain, std::string const &remote_domain) const {
    std::string binoutput;
    binoutput.resize(20);
    std::string const &key = dialback_secret();
    std::string concat = id + '|' + local_domain + '|' + remote_domain;
    HMAC(EVP_sha1(), reinterpret_cast<const unsigned char *>(key.data()), key.length(),
         reinterpret_cast<const unsigned char *>(concat.data()), concat.length(),
         const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(binoutput.data())), nullptr);
    std::string hexoutput;
    for (unsigned char c : binoutput) {
        int low = c & 0x0F;
        int high = (c & 0xF0) >> 4;
        hexoutput += ((high < 0x0A) ? '0' : ('a' - 10)) + high;
        hexoutput += ((low < 0x0A) ? '0' : ('a' - 10)) + low;
    }
    assert(hexoutput.length() == 40);
    m_logger->debug("Dialback key id {} :: {} | {}", id, local_domain, remote_domain);
    return hexoutput;
}

Config const &Config::config() {
    return *s_config;
}

void Config::dns_init() const {
    // Libunbound initialization.
    const_cast<Config *>(this)->m_ub_ctx = ub_ctx_create();
    if (!m_ub_ctx) {
        throw std::runtime_error("Couldn't start resolver");
    }
    int retval;
    if ((retval = ub_ctx_async(m_ub_ctx, 1)) != 0) {
        throw std::runtime_error(ub_strerror(retval));
    }
    if ((retval = ub_ctx_resolvconf(m_ub_ctx, NULL)) != 0) {
        throw std::runtime_error(ub_strerror(retval));
    }
    if ((retval = ub_ctx_hosts(m_ub_ctx, NULL)) != 0) {
        throw std::runtime_error(ub_strerror(retval));
    }
    if (!m_dns_keys.empty()) {
        if ((retval = ub_ctx_add_ta_file(m_ub_ctx, const_cast<char *>(m_dns_keys.c_str()))) != 0) {
            throw std::runtime_error(ub_strerror(retval));
        }
    }
}

std::shared_ptr<spdlog::logger> Config::logger(std::string const & logger_name) const {
    auto sinks = m_root_logger->sinks();
    auto logger = std::make_shared<spdlog::logger>(logger_name, begin(sinks), end(sinks));
    logger->flush_on(spdlog::level::trace);
    logger->set_level(spdlog::level::trace);
    return logger;
}

/*
 * DNS resolver functions.
 */

namespace {
    class UBResult {
        /* Quick guard class. */
    public:
        struct ub_result *result;

        UBResult(struct ub_result *r) : result(r) {}

        ~UBResult() { ub_resolve_free(result); }
    };

    void srv_lookup_done_cb(void *x, int err, struct ub_result *result) {
        UBResult r{result};
        reinterpret_cast<Config::Domain *>(x)->srv_lookup_done(err, result);
    }

    void a_lookup_done_cb(void *x, int err, struct ub_result *result) {
        UBResult r{result};
        reinterpret_cast<Config::Domain *>(x)->a_lookup_done(err, result);
    }

    void tlsa_lookup_done_cb(void *x, int err, struct ub_result *result) {
        UBResult r{result};
        reinterpret_cast<Config::Domain *>(x)->tlsa_lookup_done(err, result);
    }
}

void Config::Domain::tlsa(std::string const &ahostname, unsigned short port, DNS::TlsaRR::CertUsage certUsage,
                          DNS::TlsaRR::Selector selector, DNS::TlsaRR::MatchType matchType, std::string const &value) {
    std::ostringstream out;
    if (ahostname.empty()) throw std::runtime_error("Empty hostname in TLSA override");
    std::string hostname = ahostname;
    if (hostname[hostname.length() - 1] != '.') hostname += '.';
    out << "_" << port << "._tcp." << hostname;
    std::string domain = toASCII(out.str());
    auto tlsait = m_tlsarecs.find(domain);
    DNS::Tlsa *tlsa;
    if (tlsait == m_tlsarecs.end()) {
        auto tlsan = std::make_unique<DNS::Tlsa>();
        tlsan->dnssec = true;
        tlsan->domain = domain;
        tlsa = tlsan.get();
        m_tlsarecs[domain] = std::move(tlsan);
    } else {
        tlsa = tlsait->second.get();
    }
    DNS::TlsaRR rr;
    rr.certUsage = certUsage;
    rr.matchType = matchType;
    rr.selector = selector;
    // Match data. Annoying.
    // If the match type was a hash, it'll be an inline hash.
    switch (matchType) {
        case DNS::TlsaRR::Sha256:
        case DNS::TlsaRR::Sha512: {
            unsigned char byte = 0;
            bool flip = false;
            for (auto c : value) {
                if (std::isdigit(c)) {
                    byte += (c - '0');
                } else if (c >= 'A' && c <= 'F') {
                    byte += (c - 'A' + 0xA);
                } else if (c >= 'a' && c <= 'f') {
                    byte += (c - 'a' + 0xA);
                } else {
                    continue;
                }
                if (flip) {
                    rr.matchData += byte;
                    byte = 0;
                    flip = false;
                } else {
                    byte <<= 4;
                    flip = true;
                }
            }
        }
            break;
        default: {
            bool read_ok = false;
            if (value.find('\n') == std::string::npos && value.find('/') != std::string::npos) {
                std::ifstream in(value);
                rr.matchData.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
                if (!rr.matchData.empty()) {
                    read_ok = true;
                }
            }
            if (!read_ok) {
                rr.matchData = base64_decode(value);
            }
        }
    }
    tlsa->rrs.push_back(rr);
}

std::vector<DNS::Tlsa> const &Config::Domain::tlsa() const {
    if (m_tlsa_all.empty()) {
        auto recs = &m_tlsarecs;
        if (recs->empty()) {
            for (Domain const *d = this; d; d = d->m_parent) {
                recs = &d->m_tlsarecs;
                if (!recs->empty()) break;
            }
        }
        for (auto &item : *recs) {
            m_tlsa_all.push_back(*item.second);
        }
    }
    return m_tlsa_all;
}

void Config::Domain::tlsa_lookup_done(int err, struct ub_result *result) {
    std::string error;
    logger().debug("TLSA Response for {}", result->qname);
    if (err != 0) {
        error = ub_strerror(err);
    } else if (!result->havedata) {
        error = "No TLSA records present";
    } else if (result->bogus) {
        error = std::string("Bogus: ") + result->why_bogus;
    } else if (!result->secure && m_dnssec_required) {
        error = "DNSSEC required but unsigned";
    } else {
        DNS::Tlsa tlsa;
        tlsa.dnssec = !!result->secure;
        tlsa.domain = result->qname;
        for (int i = 0; result->data[i]; ++i) {
            DNS::TlsaRR rr;
            rr.certUsage = static_cast<DNS::TlsaRR::CertUsage>(result->data[i][0]);
            rr.selector = static_cast<DNS::TlsaRR::Selector>(result->data[i][1]);
            rr.matchType = static_cast<DNS::TlsaRR::MatchType>(result->data[i][2]);
            rr.matchData.assign(result->data[i] + 3, result->len[i] - 3);
            tlsa.rrs.push_back(rr);
            logger().debug("Data[{}]: ({} bytes) {}:{}:{}::{}", i, result->len[i], rr.certUsage, rr.selector, rr.matchType, rr.matchData);
        }
        m_tlsa_pending[tlsa.domain].emit(&tlsa);
        return;
    }
    logger().info("DNS Error: {}", error);
    DNS::Tlsa tlsa;
    tlsa.error = error;
    tlsa.domain = result->qname;
    m_tlsa_pending[tlsa.domain].emit(&tlsa);
}

namespace {
    void srv_sort(DNS::Srv &srv) {
        std::vector<DNS::SrvRR> tmp = std::move(srv.rrs);
        std::sort(tmp.begin(), tmp.end(), [](DNS::SrvRR const &a, DNS::SrvRR const &b) {
            return a.priority < b.priority;
        });
        srv.rrs = std::vector<DNS::SrvRR>();
        std::map<unsigned short, int> weights;
        for (auto const &rr : tmp) {
            weights[rr.priority] += rr.weight;
        }
        std::default_random_engine random(std::random_device{}());
        std::uniform_int_distribution<> dist(0, 65535);
        bool any;
        do {
            int prio = -1;
            int r = dist(random);
            any = false;
            for (auto &rr : tmp) {
                if (rr.port == 0) continue;
                if (prio > 0 && prio != rr.priority) break; // We've not completed the last priority level yet.
                if (weights[rr.priority] == rr.weight) {
                    // Pick the only one.
                    srv.rrs.push_back(rr);
                    rr.port = 0;
                    weights[rr.priority] = 0;
                    continue;
                }
                if (r % weights[rr.priority] <= rr.weight) {
                    srv.rrs.push_back(rr);
                    rr.port = 0;
                    weights[rr.priority] -= rr.weight;
                } else {
                    any = true;
                    prio = rr.priority;
                }
            }
        } while (any);
    }
}

void
Config::Domain::srv(std::string const &hostname, unsigned short priority, unsigned short weight, unsigned short port, bool tls) {
    if (!m_srvrec) {
        m_srvrec.reset(new DNS::Srv);
        std::string domain = toASCII(
                "_xmpp-server._tcp." + m_domain + "."); // Confusing: We fake a non-tls SRV record with TLS set in RR.
        m_srvrec->dnssec = true;
        m_srvrec->domain = domain;
    }
    DNS::SrvRR rr;
    rr.priority = priority;
    rr.weight = weight;
    rr.port = port;
    rr.hostname = toASCII(hostname);
    if (rr.hostname[rr.hostname.length() - 1] != '.') rr.hostname += '.';
    rr.tls = tls;
    m_srvrec->rrs.push_back(rr);
}

void Config::Domain::srv_lookup_done(int err, struct ub_result *result) {
    std::string error;
    if (err != 0) {
        error = ub_strerror(err);
    } else if (!result->havedata) {
        error = "No SRV records present";
    } else if (result->bogus) {
        error = std::string("Bogus: ") + result->why_bogus;
    } else if (!result->secure && m_dnssec_required) {
        error = "DNSSEC required but unsigned";
    } else {
        DNS::Srv &srv = m_current_srv;
        bool xmpps = false;
        srv.dnssec = srv.dnssec && !!result->secure;
        srv.domain = result->qname;
        if (srv.domain.find("_xmpps") == 0) {
            xmpps = true;
            srv.xmpps = true;
            srv.domain = std::string("_xmpp") + (srv.domain.c_str() + 6);
        } else {
            srv.xmpp = true;
        }
        for (int i = 0; result->data[i]; ++i) {
            DNS::SrvRR rr;
            rr.priority = ntohs(*reinterpret_cast<unsigned short *>(result->data[i]));
            rr.weight = ntohs(*reinterpret_cast<unsigned short *>(result->data[i] + 2));
            rr.port = ntohs(*reinterpret_cast<unsigned short *>(result->data[i] + 4));
            rr.tls = xmpps;
            for (int x = 6; result->data[i][x]; x += result->data[i][x] + 1) {
                rr.hostname.append(result->data[i] + x + 1, result->data[i][x]);
                rr.hostname += ".";
            }
            srv.rrs.push_back(rr);
            logger().debug("Data[{}]: ({} bytes) {}:{}:{}::{}", i, result->len[i], rr.priority, rr.weight, rr.port, rr.hostname);
        }
        if (srv.xmpp && srv.xmpps) {
            srv_sort(srv);
            m_srv_pending.emit(&srv);
        }
        return;
    }
    logger().info("DNS Error: {}");
    m_current_srv.domain = result->qname;
    if (err == 0 && !result->havedata) {
        if (m_current_srv.xmpps || m_current_srv.xmpp) {
            // We have done (precisely) one, so set this flag.
            m_current_srv.nxdomain = true;
        }
    } else {
        m_current_srv.nxdomain = false;
    }
    if (m_current_srv.domain.find("_xmpps") == 0) {
        m_current_srv.xmpps = true;
        m_current_srv.domain = std::string("_xmpp") + (m_current_srv.domain.c_str() + 6);
    } else {
        m_current_srv.xmpp = true;
    }
    if (m_current_srv.xmpp && m_current_srv.xmpps) {
        if (m_current_srv.rrs.empty()) {
            if (m_current_srv.nxdomain) {
                // Synthesize an SRV.
                logger().debug("Synthetic SRV for {} : {}", m_current_srv.domain, m_current_srv.error);
                DNS::SrvRR rr;
                rr.port = 5269;
                rr.hostname =
                        m_current_srv.domain.c_str() + sizeof("_xmpp-server._tcp.") - 1; // Trim "_xmpp-server._tcp."
                METRE_LOG(Log::DEBUG, "Set to 0 0 5269 " << rr.hostname);
                m_current_srv.rrs.push_back(rr);
                m_current_srv.error.clear();
            }
        }
        if (m_current_srv.rrs.empty()) {
            DNS::Srv srv;
            srv.error = error;
            srv.domain = result->qname;
            srv.dnssec = srv.dnssec && !!result->secure;
            m_srv_pending.emit(&srv);
        } else {
            srv_sort(m_current_srv);
            m_current_srv.dnssec = m_current_srv.dnssec && !!result->secure;
            m_srv_pending.emit(&m_current_srv);
        }
    }
}

void Config::Domain::a_lookup_done(int err, struct ub_result *result) {
    METRE_LOG(Log::INFO, "Lookup for " << result->qname << " complete.");
    std::string error;
    if (err != 0) {
        error = ub_strerror(err);
    } else if (!result->havedata) {
        error = "No A records present";
    } else if (result->bogus) {
        error = std::string("Bogus: ") + result->why_bogus;
    } else if (!result->secure && m_dnssec_required) {
        error = "DNSSEC required but unsigned";
    } else {
        DNS::Address &a = m_current_arec;
        if (a.hostname != result->qname) {
            a.error = "";
            a.dnssec = !!result->secure;
            a.hostname = result->qname;
            a.addr.clear();
            a.ipv4 = a.ipv6 = false;
        } else {
            a.dnssec = a.dnssec && !!result->secure;
            a.error = "";
        }
        METRE_LOG(Log::DEBUG, "... Success for " << result->qtype);
        if (result->qtype == 1) {
            m_current_arec.ipv4 = true;
            for (int i = 0; result->data[i]; ++i) {
                a.addr.emplace_back();
                struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&*a.addr.rbegin());
                sin->sin_family = AF_INET;
#ifdef METRE_WINDOWS
                sin->sin_addr = *reinterpret_cast<struct in_addr *>(result->data[i]);
#else
                sin->sin_addr.s_addr = *reinterpret_cast<in_addr_t *>(result->data[i]);
#endif
            }
        } else if (result->qtype == 28) {
            m_current_arec.ipv6 = true;
            for (int i = 0; result->data[i]; ++i) {
                a.addr.emplace(a.addr.begin());
                struct sockaddr_in6 *sin = reinterpret_cast<struct sockaddr_in6 *>(&*a.addr.begin());
                sin->sin6_family = AF_INET6;
                memcpy(sin->sin6_addr.s6_addr, result->data[i], 16);
            }
        }
        if (m_current_arec.ipv4 && m_current_arec.ipv6) {
            m_a_pending[a.hostname].emit(&a);
        }
        return;
    }
    METRE_LOG(Log::DEBUG, "... Failure for " << result->qtype << " with " << error);
    if (m_current_arec.hostname != result->qname) {
        m_current_arec.error = error;
        m_current_arec.dnssec = !!result->secure;
        m_current_arec.hostname = result->qname;
        m_current_arec.addr.clear();
        m_current_arec.ipv4 = m_current_arec.ipv6 = false;
    }
    switch (result->qtype) {
        case 1:
            m_current_arec.ipv4 = true;
            break;
        case 28:
            m_current_arec.ipv6 = true;
    }
    if (m_current_arec.ipv4 && m_current_arec.ipv6) {
        if (m_current_arec.addr.empty()) {
            m_current_arec.error = error;
        }
        m_a_pending[m_current_arec.hostname].emit(&m_current_arec);
    }
}

namespace {
    void resolve_async(Config::Domain const *domain, std::string const &record, int rrtype, ub_callback_type cb) {
        int retval;
        if ((retval = ub_resolve_async(Config::config().ub_ctx(), const_cast<char *>(record.c_str()), rrtype, 1,
                                       const_cast<void *>(reinterpret_cast<const void *>(domain)), cb, NULL)) < 0) {
            throw std::runtime_error(std::string("While resolving ") + record + ": " + ub_strerror(retval));
        }
    }
}

Config::addr_callback_t &Config::Domain::AddressLookup(std::string const &ihostname) const {
    std::string hostname = toASCII(ihostname);
    METRE_LOG(Metre::Log::DEBUG, "A/AAAA lookup for " << hostname << " context:" << m_domain);
    auto arecs = &m_host_arecs;
    if (arecs->empty()) {
        for (Domain const *d = this; d; d = d->m_parent) {
            METRE_LOG(Metre::Log::DEBUG, "DNS overrides empty, trying parent {" << d->domain() << "}");
            arecs = &d->m_host_arecs;
            if (!arecs->empty()) break;
        }
    }
    auto it = arecs->find(hostname);
    if (it != arecs->end()) {
        auto addr = &*(it->second);
        Router::defer([addr, this]() {
            m_a_pending[addr->hostname].emit(addr);
        });
        METRE_LOG(Metre::Log::DEBUG, "Using DNS override");
    } else {
        m_current_arec.hostname = "";
        m_current_arec.addr.clear();
        m_current_arec.ipv6 = m_current_arec.ipv4 = false;
        resolve_async(this, hostname, 28, a_lookup_done_cb);
        resolve_async(this, hostname, 1, a_lookup_done_cb);
    }
    return m_a_pending[hostname];
}

Config::srv_callback_t &Config::Domain::SrvLookup(std::string const &base_domain) const {
    std::string domain = toASCII("_xmpp-server._tcp." + base_domain + ".");
    std::string domains = toASCII("_xmpps-server._tcp." + base_domain + ".");
    METRE_LOG(Metre::Log::DEBUG, "SRV lookup for " << domain << " context:" << m_domain);
    auto rec = &*m_srvrec;
    if (!rec) {
        for (Domain const *d = this; d; d = d->m_parent) {
            METRE_LOG(Metre::Log::DEBUG, "DNS overrides empty, trying parent {" << d->domain() << "}");
            rec = &*d->m_srvrec;
            if (rec) break;
        }
    }
    if (rec) {
        Router::defer([rec, this]() {
            m_srv_pending.emit(rec);
        });
        METRE_LOG(Metre::Log::DEBUG, "Using DNS override");
    } else if (base_domain.empty()) {
        srv_callback_t &cb = m_srv_pending;
        Router::defer([&cb]() {
            DNS::Srv r;
            r.error = "Empty Domain - DNS aborted";
            cb.emit(&r);
        });
    } else if (m_type == X2X) {
        srv_callback_t &cb = m_srv_pending;
        Router::defer([&cb]() {
            DNS::Srv r;
            r.error = "X2X - DNS aborted";
            cb.emit(&r);
        });
    } else {
        m_current_srv.xmpp = m_current_srv.xmpps = false;
        m_current_srv.rrs.clear();
        m_current_srv.dnssec = true;
        m_current_srv.error.clear();
        resolve_async(this, domain, 33, srv_lookup_done_cb);
        resolve_async(this, domains, 33, srv_lookup_done_cb);
    }
    return m_srv_pending;
}

Config::tlsa_callback_t &Config::Domain::TlsaLookup(unsigned short port, std::string const &base_domain) const {
    std::ostringstream out;
    out << "_" << port << "._tcp." << base_domain;
    std::string domain = toASCII(out.str());
    METRE_LOG(Metre::Log::DEBUG, "TLSA lookup for " << domain);
    auto recs = &m_tlsarecs;
    if (recs->empty()) {
        for (Domain const *d = this; d; d = d->m_parent) {
            METRE_LOG(Metre::Log::DEBUG, "DNS overrides empty, trying parent {" << d->domain() << "}");
            recs = &d->m_tlsarecs;
            if (!recs->empty()) break;
        }
    }
    auto it = recs->find(domain);
    if (it != recs->end()) {
        auto addr = &*(it->second);
        Router::defer([addr, this]() {
            m_tlsa_pending[addr->domain].emit(addr);
        });
        METRE_LOG(Metre::Log::DEBUG, "Using DNS override");
    } else if (m_type == X2X) {
        auto &cb = m_tlsa_pending[domain];
        Router::defer([&cb]() {
            DNS::Tlsa r;
            r.error = "X2X - DNS aborted";
            cb.emit(&r);
        });
    } else {
        resolve_async(this, domain, 52, tlsa_lookup_done_cb);
    }
    return m_tlsa_pending[domain];
}
