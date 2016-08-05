#include "feature.h"
#include "stanza.h"
#include "xmppexcept.h"
#include "router.h"
#include "netsession.h"
#include <memory>
#include "config.h"

#include <openssl/sha.h>
#include <openssl/sha.h>
#include <log.h>

using namespace Metre;
using namespace rapidxml;

namespace {
	const std::string db_ns = "jabber:server:dialback";
	const std::string db_feat_ns = "urn:xmpp:features:dialback";

	class NewDialback : public Feature {
	public:
		NewDialback(XMLStream & s) : Feature(s) {}
		class Description : public Feature::Description<NewDialback> {
		public:
			Description() : Feature::Description<NewDialback>(db_feat_ns, FEAT_AUTH_FALLBACK) {};
			virtual void offer(xml_node<> * node, XMLStream & s) {
				if (!s.secured() && (Config::config().domain(s.local_domain()).require_tls() || Config::config().domain(s.remote_domain()).require_tls())) {
					return;
				}
				xml_document<> * d = node->document();
				auto feature = d->allocate_node(node_element, "dialback");
				feature->append_attribute(d->allocate_attribute("xmlns", db_feat_ns.c_str()));
				auto errors = d->allocate_node(node_element, "errors");
				feature->append_node(errors);
				node->append_node(feature);
			}
		};
		bool negotiate(rapidxml::xml_node<> *) override { // Note that this offer, unusually, can be nullptr.
			if (!m_stream.secured() && (Config::config().domain(m_stream.local_domain()).require_tls() || Config::config().domain(m_stream.remote_domain()).require_tls())) {
				METRE_LOG(Metre::Log::DEBUG, "Supressed dialback due to missing required TLS");
				return false;
			}
			m_stream.set_auth_ready();
			return false;
		}
		bool handle(rapidxml::xml_node<> *) override {
			throw Metre::unsupported_stanza_type("Wrong namespace for dialback.");
		}
	};

	class Dialback : public Feature, public sigslot::has_slots<> {
	public:
		Dialback(XMLStream & s) : Feature(s) {}
		class Description : public Feature::Description<Dialback> {
		public:
			Description() : Feature::Description<Dialback>(db_ns, FEAT_AUTH) {};
		};

        /*
         * Temporary store for keys, because - bizarrely - a std::string doesn't
         * appear to be getting captured by value.
         */
        std::set<std::string> m_keys;

		/**
		 * Inbound handling.
		 */
		void result_step(Route & route, std::string const & key) {
			route.onNamesCollated.disconnect(this);
			// Shortcuts here.
			if (m_stream.tls_auth_ok(route)) {
				xml_document<> d;
				auto result = d.allocate_node(node_element, "db:result");
				result->append_attribute(d.allocate_attribute("from", route.local().c_str()));
				result->append_attribute(d.allocate_attribute("to", route.domain().c_str()));
				result->append_attribute(d.allocate_attribute("type", "valid"));
				d.append_node(result);
				m_stream.send(d);
				m_stream.s2s_auth_pair(route.local(), route.domain(), INBOUND, XMLStream::AUTHORIZED);
			}
			Config::Domain const & from_domain = Config::config().domain(route.domain());
			if (!from_domain.auth_dialback()) {
				// TODO !!!!!
				throw Metre::host_unknown("Will not perform dialback with you.");
			}
			m_stream.s2s_auth_pair(route.local(), route.domain(), INBOUND, XMLStream::REQUESTED);
			// With syntax done, we should send the key:
            route.transmit(std::unique_ptr<Verify>(
                    new Verify(route.domain(), route.local(), m_stream.stream_id(), key, m_stream)));
            m_keys.erase(key);
		}

		void result(rapidxml::xml_node<> * node) {
			/*
			 * This is a request to authenticate, using the current key.
			 * We can shortcut this in a number of ways, but for now, let's do it longhand.
			 */
			// Should be a key here:
			const char * key = node->value();
			if (!key || !key[0]) {
				throw Metre::unsupported_stanza_type("Missing key");
			}
			// And a from/to:
			auto from = node->first_attribute("from");
			auto to = node->first_attribute("to");
			if (!(from && to)) {
				throw Metre::unsupported_stanza_type("Missing mandatory attributes");
			}
			Jid fromjid(from->value());
			Jid tojid(to->value());
			Config::Domain const & from_domain = Config::config().domain(fromjid.domain());
			if (from_domain.transport_type() != S2S) {
				throw Metre::host_unknown("Nice try.");
			}
			m_stream.check_domain_pair(fromjid.domain(), tojid.domain());
			if (!m_stream.secured() && Config::config().domain(tojid.domain()).require_tls()) {
				throw Metre::host_unknown("Domain requires TLS");
			}
			// Need to perform name collation:
			std::shared_ptr<Route> & route = RouteTable::routeTable(tojid).route(fromjid);
            m_keys.insert(key);
            const char *keytmp = m_keys.find(key)->c_str();
            route->onNamesCollated.connect(this, [=](Route &r) {
                result_step(r, keytmp);
			});
			route->collateNames();
		}

		void result_valid(rapidxml::xml_node<> * node) {
			auto to_att = node->first_attribute("to");
			if (!to_att || !to_att->value()) throw std::runtime_error("Missing to on db:result:valid");
			std::string to = to_att->value();
			auto from_att = node->first_attribute("from");
			if (!from_att || !from_att->value()) throw std::runtime_error("Missing from on db:result:valid");
			std::string from = from_att->value();
			if (m_stream.s2s_auth_pair(to, from, OUTBOUND) >= XMLStream::REQUESTED) {
				m_stream.s2s_auth_pair(to, from, OUTBOUND, XMLStream::AUTHORIZED);
			}
		}

		void result_invalid(rapidxml::xml_node<> * node) {
			throw std::runtime_error("Unimplemented");
		}

		void result_error(rapidxml::xml_node<> * node) {
			throw std::runtime_error("Unimplemented");
		}

		void verify(rapidxml::xml_node<> * node) {
			auto id_att = node->first_attribute("id");
			if (!id_att || !id_att->value()) throw std::runtime_error("Missing id on db:result:valid");
			std::string id = id_att->value();
			// TODO : Validate stream to/from
			auto to_att = node->first_attribute("to");
			if (!to_att || !to_att->value()) throw std::runtime_error("Missing to on db:result:valid");
			std::string to = to_att->value();
			auto from_att = node->first_attribute("from");
			if (!from_att || !from_att->value()) throw std::runtime_error("Missing from on db:result:valid");
			std::string from = from_att->value();
			const char * validity="invalid";
			std::string expected = Config::config().dialback_key(id, to, from);
			if (node->value() == expected) validity="valid";
			xml_document<> d;
			auto vrfy = d.allocate_node(node_element, "db:verify");
			vrfy->append_attribute(d.allocate_attribute("from", to.c_str()));
			vrfy->append_attribute(d.allocate_attribute("to", from.c_str()));
			vrfy->append_attribute(d.allocate_attribute("id", id.c_str()));
			vrfy->append_attribute(d.allocate_attribute("type", validity));
			d.append_node(vrfy);
			m_stream.send(d);
		}

		void verify_valid(rapidxml::xml_node<> * node) {
			if (m_stream.direction() != OUTBOUND) throw Metre::unsupported_stanza_type("db:verify response on inbound stream");
			auto id_att = node->first_attribute("id");
			if (!id_att || !id_att->value()) throw std::runtime_error("Missing id on verify");
			std::string id = id_att->value();
			std::shared_ptr<NetSession> session = Router::session_by_stream_id(id);
			if (!session) throw std::runtime_error("Session not found");
			XMLStream & stream = session->xml_stream();
			// TODO : Validate stream to/from
			auto to_att = node->first_attribute("to");
			if (!to_att || !to_att->value()) throw std::runtime_error("Missing to on verify");
			std::string to = to_att->value();
			auto from_att = node->first_attribute("from");
			if (!from_att || !from_att->value()) throw std::runtime_error("Missing from on verify");
			std::string from = from_att->value();
			if (stream.s2s_auth_pair(to, from, INBOUND) >= XMLStream::REQUESTED) {
				xml_document<> d;
				auto result = d.allocate_node(node_element, "db:result");
				result->append_attribute(d.allocate_attribute("from", to.c_str()));
				result->append_attribute(d.allocate_attribute("to", from.c_str()));
				result->append_attribute(d.allocate_attribute("type", "valid"));
				d.append_node(result);
				stream.send(d);
				stream.s2s_auth_pair(to, from, INBOUND, XMLStream::AUTHORIZED);
			}
		}

		void verify_invalid(rapidxml::xml_node<> * node) {
			throw std::runtime_error("Unimplemented");
		}

		bool handle(rapidxml::xml_node<> * node) {
			xml_document<> * d = node->document();
			d->fixup<parse_default>(node, true);
			std::string stanza = node->name();
			std::optional<std::string> type;
			if (auto type_str = node->first_attribute("type")) {
				type.emplace(type_str->value());
			}
			if (stanza == "result") {
				if (type) {
					if (*type == "valid") {
						result_valid(node);
					} else if(*type == "invalid") {
						result_invalid(node);
					} else if(*type == "error") {
						result_error(node);
					} else {
						throw Metre::unsupported_stanza_type("Unknown type attribute to db:result");
					}
				} else {
					result(node);
				}
			} else if (stanza == "verify") {
				if (type) {
					if (*type == "valid") {
						verify_valid(node);
					} else if (*type == "invalid") {
						verify_invalid(node);
					} else {
						throw Metre::unsupported_stanza_type("Unknown type attribute to db:verify");
					}
				} else {
					verify(node);
				}
			}  else {
				throw Metre::unsupported_stanza_type("Unknown dialback element");
			}
			return true;
		}
	};

	bool declared_classic = Feature::declare<Dialback>(S2S);
	bool declared_new = Feature::declare<NewDialback>(S2S);
}
