#include "router.h"
#include "dns.h"
#include "xmlstream.h"
#include "netsession.h"
#include "log.h"
#include "config.h"

#include <unordered_map>
#include <algorithm>

using namespace Metre;

Route::Route(Jid const & from, Jid const & to) : m_local(from), m_domain(to) {
  METRE_LOG(Metre::Log::DEBUG, "Route created, local is " << m_local.domain() << " remote is " << m_domain.domain());
}

namespace {
  bool check_verify(Route & r, std::shared_ptr<NetSession> const & vrfy) {
    if(vrfy) {
      if (vrfy->xml_stream().auth_ready()) {
        r.SessionDialback(vrfy->xml_stream());
        return true;
      } else {
        vrfy->xml_stream().onAuthReady.connect(&r, &Route::SessionDialback);
      }
    }
    return false;
  }


  bool check_to(Route & r, std::shared_ptr<NetSession> const & to) {
    if (to) {
      switch (to->xml_stream().s2s_auth_pair(r.local(), r.domain(), OUTBOUND)) {
      case XMLStream::AUTHORIZED:
        r.SessionAuthenticated(to->xml_stream());
        return true;
      default:
        if (!to->xml_stream().auth_ready()) {
          to->xml_stream().onAuthReady.connect(&r, &Route::SessionDialback);
        } else {
          /// Send a dialback request or something.
          std::string key = Config::config().dialback_key(to->xml_stream().stream_id(), r.local(), r.domain());
          rapidxml::xml_document<> d;
          auto dbr = d.allocate_node(rapidxml::node_element, "db:result");
          dbr->append_attribute(d.allocate_attribute("to", r.domain().c_str()));
          dbr->append_attribute(d.allocate_attribute("from", r.local().c_str()));
          dbr->value(key.c_str(), key.length());
          d.append_node(dbr);
          to->xml_stream().send(d);
          to->xml_stream().s2s_auth_pair(r.local(), r.domain(), OUTBOUND, XMLStream::REQUESTED);
        }
      case XMLStream::REQUESTED:
        to->xml_stream().onAuthenticated.connect(&r, &Route::SessionAuthenticated);
      }
    }
    return false;
  }
}

void Route::transmit(std::unique_ptr<Verify> v) {
  auto vrfy = m_vrfy.lock();
  if(check_verify(*this, vrfy)) {
      if (!m_dialback.empty()) {
          v->freeze();
          m_dialback.push_back(std::move(v));
          return;
      } else {
          vrfy->xml_stream().send(std::move(v));
      }
  } else {
    // TODO Look for an existing session and use that.
    // Otherwise, start SRV lookups.
      v->freeze();
    m_dialback.push_back(std::move(v));
    Config::config().domain(m_domain.domain()).SrvLookup(m_domain.domain()).connect(this, &Route::SrvResult);
  }

}
void Route::transmit(std::unique_ptr<Stanza> s) {
  auto to = m_to.lock();
  if (check_to(*this, to)) {
      if (!m_stanzas.empty()) {
          s->freeze();
          m_stanzas.push_back(std::move(s));
          METRE_LOG(Metre::Log::DEBUG, "Queued stanza (check) for " << m_local.domain() << "=>" << m_domain.domain());
          return;
      } else {
          to->xml_stream().send(std::move(s));
      }
  } else if (!to) {
    if(!m_vrfy.expired()) {
      std::shared_ptr<NetSession> vrfy(m_vrfy);
      m_to = vrfy;
      transmit(std::move(s)); // Retry
      return;
    }
    // TODO Look for an existing session, etc.
    std::shared_ptr<NetSession> dom = Router::session_by_domain(m_domain.domain());
    if (dom) {
      m_to = dom;
      transmit(std::move(s)); // Retry;
      return;
    }
      s->freeze();
    m_stanzas.push_back(std::move(s));
    METRE_LOG(Metre::Log::DEBUG, "Queued stanza (fallback) for " << m_local.domain() << "=>" << m_domain.domain());
    // TODO : Timeout.
    Config::Domain const & conf = Config::config().domain(m_domain.domain());
    if (conf.transport_type() == S2S) {
      doSrvLookup();
    }
    // Otherwise wait.
  } else { // Got a to but it's not ready yet.
      s->freeze();
    m_stanzas.push_back(std::move(s));
      METRE_LOG(Metre::Log::DEBUG, "Queued stanza (to) for " << m_local.domain() << "=>" << m_domain.domain());
  }
}

void Route::doSrvLookup() {
  if (m_srv.domain.empty() || !m_srv.error.empty()) {
    Config::config().domain(m_domain.domain()).SrvLookup(m_domain.domain()).connect(this, &Route::SrvResult);
  } else {
    SrvResult(&m_srv);
  }
}

void Route::collateNames() {
  if (m_srv.domain.empty() || !m_srv.error.empty()) {
    // No SRV record yet, look it up.
    doSrvLookup();
  } else {
    // Have a SRV. Was it DNSSEC signed?
    if (!m_srv.dnssec) {
      onNamesCollated.emit(*this);
    }
    // Do we have TLSAs yet?
    if (m_tlsa.size() == m_srv.rrs.size()) {
      onNamesCollated.emit(*this);
    }
  }
}

void Route::SrvResult(DNS::Srv const * srv) {
  METRE_LOG(Metre::Log::DEBUG, "Got SRV");
  if (!srv->error.empty()) {
    METRE_LOG(Metre::Log::WARNING, "Got an error during SRV: " << srv->error);
    return;
  }
  m_srv = *srv;
  // Scan through TLSA records if DNSSEC has been used.
  if (m_srv.dnssec) {
    for (auto & rr : m_srv.rrs) {
      Config::config().domain(m_domain.domain()).TlsaLookup(rr.port, rr.hostname).connect(this, &Route::TlsaResult);
    }
  } else {
    onNamesCollated.emit(*this);
  }
  auto vrfy = m_vrfy.lock();
  if (vrfy) {
    if (m_to.expired()) m_to = vrfy;
    check_to(*this, m_to.lock());
    return;
  }
  m_rr = m_srv.rrs.begin();
  METRE_LOG(Metre::Log::DEBUG, "Should look for " << (*m_rr).hostname << ":" << (*m_rr).port);
  std::shared_ptr<NetSession> sesh = Router::session_by_address((*m_rr).hostname, (*m_rr).port);
  if (sesh) {
    if (m_vrfy.expired()) m_vrfy = sesh;
    check_verify(*this, sesh);
    if (m_to.expired()) m_to = sesh;
    check_to(*this, sesh);
    return;
  }
  Config::config().domain(m_domain.domain()).AddressLookup((*m_rr).hostname).connect(this, &Route::AddressResult);
}

void Route::AddressResult(DNS::Address const * addr) {
  auto vrfy = m_vrfy.lock();
  if (vrfy) {
    return;
  }
  if (!addr->error.empty()) {
    METRE_LOG(Metre::Log::DEBUG, "Got an error during DNS: ");
    return;
  }
  m_addr = *addr;
  m_arr = m_addr.addr4.begin();
  vrfy = Router::connect(m_local.domain(), m_domain.domain(), (*m_rr).hostname, *m_arr, (*m_rr).port);
  METRE_LOG(Metre::Log::DEBUG, "Connected, " << &*vrfy);
  vrfy->xml_stream().onAuthReady.connect(this, &Route::SessionDialback);
  m_vrfy = vrfy;
  if (m_to.expired()) {
    m_to = vrfy;
    check_to(*this, vrfy);
  }
  // m_vrfy->connected.connect(...);
}

void Route::TlsaResult(const DNS::Tlsa * tlsa) {
    METRE_LOG(Metre::Log::DEBUG, "TLSA for " << tlsa->domain << ", currently " << m_tlsa.size());
    m_tlsa.erase(
            std::remove_if(m_tlsa.begin(), m_tlsa.end(), [=](DNS::Tlsa const &r) { return r.domain == tlsa->domain; }),
            m_tlsa.end());
  m_tlsa.push_back(*tlsa);
    METRE_LOG(Metre::Log::DEBUG, "TLSA for " << tlsa->domain << ", now " << m_tlsa.size());
  collateNames();
}

void Route::SessionDialback(XMLStream & stream) {
  auto vrfy = m_vrfy.lock();
  METRE_LOG(Metre::Log::DEBUG, "Stream is ready for dialback.");
  if (vrfy && &stream.session() == &*vrfy) {
    METRE_LOG(Metre::Log::DEBUG, "Stream is verify.");
    for (auto & v : m_dialback) {
      vrfy->xml_stream().send(std::move(v));
    }
    m_dialback.clear();
    if (m_to.expired()) {
      m_to = vrfy;
      check_to(*this, vrfy);
    }
  }
  auto to = m_to.lock();
  if (to) {
    if (&stream.session() == &*to) { //] && stream.s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND) == XMLStream::NONE) {
      METRE_LOG(Metre::Log::DEBUG, "Stream is to; needs dialback.");
      check_to(*this, to);
    }
  }
}

void Route::SessionAuthenticated(XMLStream & stream) {
  auto to = m_to.lock();
  if (stream.auth_ready()
      && !m_stanzas.empty()
      && &stream.session() == &*to
      && stream.s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND) == XMLStream::AUTHORIZED) {
    METRE_LOG(Metre::Log::DEBUG, "Stream now ready for stanzas.");
    for (auto & s : m_stanzas) {
      to->xml_stream().send(std::move(s));
    }
    m_stanzas.clear();
  } else {
      METRE_LOG(Metre::Log::DEBUG, "Auth, but not ready: " << stream.auth_ready() << " " << !m_stanzas.empty() << " "
                                                           << (&stream.session() == to.get()) << " "
                                                           << (stream.s2s_auth_pair(m_local.domain(), m_domain.domain(),
                                                                                    OUTBOUND) ==
                                                               XMLStream::AUTHORIZED));
  }
}

std::vector<DNS::Tlsa> const& Route::tlsa() const {
  if (m_tlsa.size()) return m_tlsa;
  return Config::config().domain(m_domain.domain()).tlsa();
}

RouteTable & RouteTable::routeTable(std::string const & d) {
  static std::unordered_map<std::string,RouteTable> rt;
  auto it = rt.find(d);
  if (it != rt.end()) return (*it).second;
  auto itp = rt.emplace(d, d);
  return (*(itp.first)).second;
}

RouteTable & RouteTable::routeTable(Jid const & j) {
  return RouteTable::routeTable(j.domain());
}

std::shared_ptr<Route> & RouteTable::route(Jid const & to) {
  // TODO This needs to be more complex once we have clients.
  if (!m_routes[to.domain()]) {
    m_routes[to.domain()] = std::shared_ptr<Route>(new Route(m_local_domain, to));
  }
  return m_routes[to.domain()];
}

RouteTable::RouteTable(std::string const & d) : m_routes(), m_local_domain(d) {
}
