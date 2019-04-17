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

#ifndef METRE_CONFIG__HPP
#define METRE_CONFIG__HPP

#include <string>
#include <map>
#include <optional>
#include <memory>
#include <list>

#include "defs.h"
#include "dns.h"
#include "spdlog/spdlog.h"

/**
 * OpenSSL forward declarations.
*/

struct ssl_ctx_st; // SSL_CTX
struct x509_store_ctx_st; // X509_STORE_CTX;

/**
 * Lib unbound.
 */

struct ub_ctx;
struct ub_result;

namespace Metre {
    class Config {
    public:
        /* DNS */
        typedef sigslot::signal<DNS::Srv const *> srv_callback_t;
        typedef sigslot::signal<DNS::Address const *> addr_callback_t;
        typedef sigslot::signal<DNS::Tlsa const *> tlsa_callback_t;

        class Domain {
            friend class ::Metre::Config;
        public:
            std::string const &domain() const {
                return m_domain;
            }

            SESSION_TYPE transport_type() const {
                return m_type;
            }

            bool forward() const {
                return m_forward;
            }

            bool require_tls() const {
                return m_require_tls;
            }

            bool block() const {
                return m_block;
            }

            bool auth_pkix() const {
                return m_auth_pkix;
            }

            bool auth_pkix_status() const {
                return m_auth_crls;
            }

            bool auth_pkix_status(bool crls) {
                return m_auth_crls = crls;
            }

            bool auth_dialback() const {
                return m_auth_dialback;
            }

            unsigned stanza_timeout() const {
                return m_stanza_timeout;
            }

            unsigned stanza_timeout(unsigned stanza_timeout) {
                return m_stanza_timeout = stanza_timeout;
            }

            unsigned connect_timeout() const {
                return m_connect_timeout;
            }

            unsigned connect_timeout(unsigned connect_timeout) {
                return m_connect_timeout = connect_timeout;
            }

            bool dnssec_required() const {
                return m_dnssec_required;
            }

            bool dnssec_required(bool d) {
                m_dnssec_required = d;
                return d;
            }

            std::string const &dhparam() const {
                return m_dhparam;
            }

            std::string const &dhparam(std::string const &d) {
                return m_dhparam = d;
            }

            std::string const &cipherlist() const {
                return m_cipherlist;
            }

            std::string const &cipherlist(std::string const &c) {
                return m_cipherlist = c;
            }

            std::optional<std::string> const &auth_secret() const {
                return m_auth_secret;
            }

            struct ssl_ctx_st *ssl_ctx() const;

            /* Loading functions */
            void x509(std::string const &chain, std::string const &key);

            void host(std::string const &hostname, uint32_t inaddr);

            void srv(std::string const &, unsigned short, unsigned short, unsigned short, bool);

            void tlsa(std::string const &hostname, unsigned short port, DNS::TlsaRR::CertUsage certUsage,
                      DNS::TlsaRR::Selector selector, DNS::TlsaRR::MatchType matchType, std::string const &value);

            std::vector<DNS::Tlsa> const &tlsa() const;

            /* DNS */
            srv_callback_t &SrvLookup(std::string const &domain) const;

            addr_callback_t &AddressLookup(std::string const &hostname) const;

            tlsa_callback_t &TlsaLookup(short unsigned int port, std::string const &hostname) const;

            /* DNS callbacks */
            void a_lookup_done(int err, struct ub_result *result);

            void srv_lookup_done(int err, struct ub_result *result);

            void tlsa_lookup_done(int err, struct ub_result *result);

            Domain(std::string const &domain, SESSION_TYPE transport_type, bool forward, bool require_tls, bool block,
                   bool auth_pkix, bool auth_dialback, bool auth_host, std::optional<std::string> &&m_auth_secret);

            Domain(Domain const &, std::string const &domain);

            Domain(Domain const &) = delete;

            Domain(Domain &&) = delete;

            ~Domain();

            FILTER_RESULT filter(SESSION_DIRECTION dir, Stanza &s) const;

            std::list<std::unique_ptr<Filter>> &filters() {
                return m_filters;
            }

            bool auth_endpoint(std::string const &ip, unsigned short port) const;

            bool auth_host() const {
                return m_auth_host;
            }

            spdlog::logger & logger() {
                if (!m_logger) {
                    m_logger = Config::config().logger("domain <" + m_domain + ">");
                }
                return *m_logger;
            }

        private:
            std::shared_ptr<spdlog::logger> m_logger;
            std::string m_domain;
            SESSION_TYPE m_type;
            bool m_forward = false;
            bool m_require_tls = true;
            bool m_block = false;
            bool m_auth_pkix = true;
            bool m_auth_crls = true;
            bool m_auth_dialback = false;
            bool m_auth_host = false;
            bool m_dnssec_required = false;
            unsigned m_stanza_timeout = 20;
            unsigned m_connect_timeout = 10;
            std::string m_dhparam;
            std::string m_cipherlist;
            std::optional<std::string> m_auth_secret;
            struct ssl_ctx_st *m_ssl_ctx = nullptr;
            std::map<std::string, std::unique_ptr<DNS::Address>> m_host_arecs;
            std::unique_ptr<DNS::Srv> m_srvrec;
            std::map<std::string, std::unique_ptr<DNS::Tlsa>> m_tlsarecs;
            mutable DNS::Address m_current_arec;
            mutable DNS::Srv m_current_srv;
            mutable std::vector<DNS::Tlsa> m_tlsa_all;
            mutable srv_callback_t m_srv_pending;
            mutable std::map<std::string, addr_callback_t> m_a_pending;
            mutable std::map<std::string, tlsa_callback_t> m_tlsa_pending;
            std::list<std::unique_ptr<Filter>> m_filters;
            std::list<struct sockaddr_storage> m_auth_endpoint;
            Domain const *m_parent = nullptr;
        };

        Config(std::string const &filename, std::string const &templog);

        ~Config();

        void write_runtime_config() const;

        std::string asString() const;

        std::string const &default_domain() const {
            return m_default_domain;
        }

        std::string const &runtime_dir() const {
            return m_runtime_dir;
        }

        std::string const &pidfile() const {
            return m_pidfile;
        }

        std::string boot_method() const {
            return m_boot;
        }

        void log_init(bool systemd = false);

        void docker_setup();

        void dns_init() const;

        Domain const &domain(std::string const &domain) const;

        void load(std::string const &filename);

        static Config const &config();

        std::string random_identifier() const;

        std::string const &dialback_secret() const {
            return m_dialback_secret;
        }

        std::string dialback_key(std::string const &id, std::string const &local_domain, std::string const &remote_domain) const;

        struct ub_ctx *ub_ctx() const {
            return m_ub_ctx;
        }

        bool fetch_pkix_status() const {
            return m_fetch_crls;
        }

        class Listener {
        public:
            SESSION_TYPE session_type;
            TLS_MODE tls_mode;
            std::string const name;
            std::string const local_domain;
            std::string const remote_domain;
            std::set<std::string> allowed_domains;
        private:
            struct sockaddr_storage m_sockaddr;
        public:
            const struct sockaddr *sockaddr() const {
                return reinterpret_cast<const struct sockaddr *>(&m_sockaddr);
            }

            Listener(std::string const &local_domain, std::string const &remote_domain, std::string const &name,
                     const char *address, unsigned short port, TLS_MODE tls, SESSION_TYPE sess);
        };

        std::list<Listener> const &listeners() const {
            return m_listeners;
        }

        spdlog::logger &logger() const {
            return *m_root_logger;
        }

        std::shared_ptr<spdlog::logger> logger(std::string const &) const;

        std::string const &database() const {
            return m_database;
        }

    private:
        static int verify_callback_cb(int preverify_ok, struct x509_store_ctx_st *);

        void create_domain(std::string const &dom);

        bool m_fetch_crls = true;
        std::string m_config_str;
        std::string m_default_domain;
        std::string m_runtime_dir;
        std::string m_data_dir;
        std::string m_dns_keys;
        std::string m_pidfile;
        std::string m_dialback_secret;
        std::string m_logfile;
        std::string m_boot;
        std::string m_database;
        std::map<std::string, std::unique_ptr<Domain>> m_domains;
        struct ub_ctx *m_ub_ctx = nullptr;
        std::list<Listener> m_listeners;
        std::shared_ptr<spdlog::logger> m_root_logger;
        std::shared_ptr<spdlog::logger> m_logger;
    };
}

#endif
