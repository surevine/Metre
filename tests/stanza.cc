#include "stanza.h"
#include "gtest/gtest.h"
#include <iostream>
#include "rapidxml_print.hpp"

using namespace Metre;

class MessageTest : public ::testing::Test {
public:
    std::unique_ptr<Message> msg;
    rapidxml::xml_document<> doc;
    std::string msg_xml = "<message xmlns='jabber:server' from='foo@example.org/lmas' to='bar@example.net/laks' type='chat' id='1234'><body>This is the body</body></message>";

    void SetUp() override {
        doc.parse<rapidxml::parse_full>(const_cast<char *>(msg_xml.c_str()));
        msg = std::make_unique<Message>(doc.first_node());
    }
};

TEST_F(MessageTest, IdMatches) {
    ASSERT_EQ(msg->id(), std::string("1234"));
}

TEST_F(MessageTest, MessageType) {
    ASSERT_EQ(msg->type(), Message::Type::CHAT);
}

TEST_F(MessageTest, MessageFrom) {
    ASSERT_EQ(msg->from().full(), "foo@example.org/lmas");
}

TEST_F(MessageTest, MessageTo) {
    ASSERT_EQ(msg->to().full(), "bar@example.net/laks");
}

TEST_F(MessageTest, MessageBody) {
    ASSERT_EQ(msg->node()->first_node("body")->value(), std::string("This is the body"));
}

class IqTest : public ::testing::Test {
public:
    std::unique_ptr<Iq> iq;
    rapidxml::xml_document<> doc;
    std::string iq_xml = "<iq xmlns='jabber:server' from='foo@example.org/lmas' to='bar@example.net/laks' type='get' id='1234'><query xmlns='urn:xmpp:ping'/></iq>";

    void SetUp() override {
        doc.parse<rapidxml::parse_full>(const_cast<char *>(iq_xml.c_str()));
        iq = std::make_unique<Iq>(doc.first_node());
    }
};

TEST_F(IqTest, Id) {
    ASSERT_EQ(iq->id(), "1234");
}

TEST_F(IqTest, Type) {
    ASSERT_EQ(iq->type(), Iq::Type::GET);
}

TEST_F(IqTest, From) {
    ASSERT_EQ(iq->from().full(), "foo@example.org/lmas");
}

TEST_F(IqTest, To) {
    ASSERT_EQ(iq->to().full(), "bar@example.net/laks");
}

TEST_F(IqTest, Name) {
    ASSERT_EQ(iq->node()->first_node()->name(), std::string("query"));
}

TEST_F(IqTest, Namespace) {
    ASSERT_EQ(iq->node()->first_node()->xmlns(), std::string("urn:xmpp:ping"));
}

#if 0
class IqGenTest : public Test {
public:
    IqGenTest() : Test("Iq Gen") {}

    bool run() {
        Iq iq(std::string("foo@example.org/lmas"), std::string("bar@example.net/laks"), Iq::GET, std::string("1234"));
        iq.payload("<ping xmlns='urn:xmpp:ping'/>");
        rapidxml::xml_document<> doc;
        iq.render(doc);
        std::string tmp;
        rapidxml::print(std::back_inserter(tmp), doc, rapidxml::print_no_indenting);
        assert::equal(tmp,
                      "<iq to=\"bar@example.net/laks\" from=\"foo@example.org/lmas\" type=\"get\" id=\"1234\"><ping xmlns='urn:xmpp:ping'/></iq>",
                      "iq/render");
        return true;
    }
};

namespace {
    MessageTest messagetest;
    IqTest iqtest;
    IqGenTest iqgentest;
}
#endif