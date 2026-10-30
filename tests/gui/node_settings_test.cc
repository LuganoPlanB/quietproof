#include "node_settings.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>

using namespace quietproof::gui;
using namespace proofs;
namespace {
int checks = 0;
void Require(bool condition, const char* label) {
  ++checks;
  if (!condition) throw std::runtime_error(label);
}
}
int main(int argc, char** argv) {
  try {
    Require(argc == 2,"fixture directory");
    const std::filesystem::path directory(argv[1]);
    std::filesystem::create_directories(directory);
    const auto path = directory/"node.conf";
    std::filesystem::remove(directory/"custom.cookie");
    std::string error;
    NodeSettings settings;
    settings.Set(NodeField::DataDirectory,directory.string());
    const char* ports[] = {"8332","18332","38332","18443","48332"};
    const char* subdirs[] = {"","testnet3/","signet/","regtest/","testnet4/"};
    for (unsigned i=0; i<5; ++i) {
      const auto configured = ConfigureNode(settings,static_cast<QuietProofNetwork>(i),&error);
      Require(configured.has_value(),"supported network");
      Require(configured->resolved.url == std::string("http://127.0.0.1:")+ports[i]+"/","default network port");
      Require(configured->resolved.cookie_path == directory.string()+"/"+subdirs[i]+".cookie","default cookie subdirectory");
      Require(configured->rpc.connect_timeout.count() == 5000 && configured->rpc.rpc_timeout.count() == 30000,"default timeouts");
    }
    Require(!ConfigureNode(settings,static_cast<QuietProofNetwork>(255),&error),"explicit supported network required");
    settings.Set(NodeField::Host,"localhost");
    settings.Set(NodeField::Port,"19000");
    settings.Set(NodeField::CookiePath,(directory/"custom.cookie").string());
    settings.Set(NodeField::Wallet,"synthetic wallet \"with quotes\"");
    settings.Set(NodeField::ConnectTimeout,"250");
    settings.Set(NodeField::RpcTimeout,"900");
    auto configured = ConfigureNode(settings,QuietProofNetwork::kSignet,&error);
    Require(configured && configured->resolved.url == "http://127.0.0.1:19000/","localhost override");
    Require(configured->resolved.cookie_path == (directory/"custom.cookie").string(),"explicit cookie wins");
    Require(configured->rpc.connect_timeout.count() == 250 && configured->rpc.rpc_timeout.count() == 900,"timeout overrides");
    Require(ConfigureNode(settings,QuietProofNetwork::kRegtest,&error)->resolved.url == configured->resolved.url,"override survives network changes");
    Require(SaveNodeSettings(path,settings),"save settings");
    struct stat metadata{};
    Require(stat(path.c_str(),&metadata) == 0 && (metadata.st_mode & 0777) == 0600,"private permissions");
    auto loaded = LoadNodeSettings(path,&error);
    Require(error.empty() && loaded.fields == settings.fields,"roundtrip nonsecret fields");
    std::ifstream stored(path);
    const std::string contents((std::istreambuf_iterator<char>(stored)),{});
    Require(contents.find("password") == std::string::npos && contents.find("__cookie__") == std::string::npos,"credentials absent");
    // Config resolution deliberately does not open cookies. A missing cookie is
    // reported by transport; changing/rotating it never changes persisted settings.
    Require(!std::filesystem::exists(directory/"custom.cookie"),"missing synthetic cookie");
    Require(ConfigureNode(settings,QuietProofNetwork::kRegtest,&error).has_value(),"resolve missing cookie without access");
    { std::ofstream cookie(directory/"custom.cookie"); cookie << "__cookie__:synthetic-first"; }
    { std::ofstream cookie(directory/"custom.cookie"); cookie << "__cookie__:synthetic-rotated"; }
    Require(LoadNodeSettings(path,&error).fields == settings.fields,"cookie rotation leaves nonsecret settings unchanged");
    for (const auto host : {"192.168.0.1","example.com","127.1","127.0.0.1:80","u:p@127.0.0.1","http://127.0.0.1/","[::]","127.0.0.1/wallet/a"}) {
      auto bad = settings;
      bad.Set(NodeField::Host,host);
      Require(!ConfigureNode(bad,QuietProofNetwork::kMainnet,&error),"invalid host");
      Require(!SaveNodeSettings(path,bad),"invalid host not persisted");
    }
    for (const auto host : {"127.0.0.1","127.2.3.4","::1","[::1]"}) {
      auto valid = settings;
      valid.Set(NodeField::Host,host);
      Require(ConfigureNode(valid,QuietProofNetwork::kMainnet,&error).has_value(),"loopback hosts");
    }
    for (const auto field : {NodeField::Port,NodeField::ConnectTimeout,NodeField::RpcTimeout}) {
      for (const auto text : {"0","-1","65536","abc","12.5"}) {
        auto bad = settings;
        bad.Set(field,text);
        Require(!ConfigureNode(bad,QuietProofNetwork::kMainnet,&error),"invalid numeric field");
      }
    }
    for (const auto text : {"", "quietproof-node=2\n", "quietproof-node=1\n0 \"localhost\"\n", "unknown=password\n"}) {
      { std::ofstream output(path); output << text; }
      Require(LoadNodeSettings(path,&error).fields == NodeSettings{}.fields && !error.empty(),"corrupted config restores defaults");
    }
    { std::ofstream output(path); output << contents << "password=synthetic\n"; }
    Require(LoadNodeSettings(path,&error).fields == NodeSettings{}.fields && !error.empty(),"extra fields rejected");
    { std::ofstream output(path); output << std::string(32769,'x'); }
    Require(LoadNodeSettings(path,&error).fields == NodeSettings{}.fields && !error.empty(),"oversize config bounded");
    settings = {};
    configured = ConfigureNode(settings,QuietProofNetwork::kTestnet4,&error);
    Require(configured && configured->resolved.url == "http://127.0.0.1:48332/" && configured->wallet.empty(),"reset defaults");
    std::cout << "Node settings: " << checks << " checks passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
