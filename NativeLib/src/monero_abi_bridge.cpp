/**
 * Copyright (c) BTCPay Monero
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Parts of this file are originally copyright (c) woodser
 *
 * Parts of this file are originally copyright (c) 2014-2019, The Monero Project
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * All rights reserved.
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
 */

#include <inttypes.h>
#include <cstring>
#include <string>
#include <string_view>
#include <stdexcept>
#include <cctype>
#include <thread>
#include "monero_abi_bridge.h"
#include "utils/monero_utils.h"
#include "wallet/monero_wallet_keys.h"
#include "wallet/monero_wallet_full.h"

// --------------------------------- NETWORK TYPE ---------------------------------

static const int MONERO_NETWORK_MAINNET = 0;
static const int MONERO_NETWORK_TESTNET = 1;
static const int MONERO_NETWORK_STAGENET = 2;

// --------------------------------- MESSAGE SIGNATURE TYPE ---------------------------------

static const int MONERO_MESSAGE_SIGN_WITH_SPEND_KEY = 0;
static const int MONERO_MESSAGE_SIGN_WITH_VIEW_KEY = 1;

// --------------------------------- PRIVATE HELPERS ---------------------------------

// thread-local storage for last api error message
static thread_local std::string last_error = "";

#define DEBUG_START()                                                             \
  try {

#define DEBUG_END()                                                               \
  } catch (const std::exception &e) {                                             \
    std::cerr << "Exception caught in function: " << __FUNCTION__                 \
          << " at " << __FILE__ << ":" << __LINE__ << std::endl                   \
          << "Message: " << e.what() << std::endl;                                \
    last_error = e.what();                                                        \
  } catch (...) {                                                                 \
    std::cerr << "Unknown exception caught in function: " << __FUNCTION__         \
          << " at " << __FILE__ << ":" << __LINE__ << std::endl;                  \
    std::abort();                                                                 \
  }

std::string to_hex(std::string_view bytes, std::string_view prefix = "0b") {
  static constexpr char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(prefix.size() + bytes.size() * 2);
  out.append(prefix);
  for (unsigned char b : bytes) {
    out.push_back(hex[b >> 4]);
    out.push_back(hex[b & 0x0F]);
  }
  return out;
}

unsigned char from_hex_character(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  throw std::invalid_argument("Invalid hex character");
}

std::string from_hex(const std::string& hex, std::string_view prefix = "0b") {
  size_t start = 0;
  if (hex.rfind(prefix, 0) == 0) {
    start = prefix.size();
  }
  if (((hex.size() - start) % 2) != 0) {
    throw std::invalid_argument("Invalid hex string length");
  }

  std::string out;
  out.reserve((hex.size() - start) / 2);
  for (size_t i = start; i < hex.size(); i += 2) {
    unsigned char high = from_hex_character(hex[i]);
    unsigned char low  = from_hex_character(hex[i + 1]);
    out.push_back(static_cast<char>((high << 4) | low));
  }
  return out;
}

bool parse_network_type(int network_type, monero_network_type& net_type) noexcept {
  if (network_type == MONERO_NETWORK_MAINNET) {
    net_type = monero_network_type::MAINNET;
  } else if (network_type == MONERO_NETWORK_TESTNET) {
    net_type = monero_network_type::TESTNET;
  } else if (network_type == MONERO_NETWORK_STAGENET) {
    net_type = monero_network_type::STAGENET;
  } else {
    return false;
  }

  return true;
}

bool parse_message_signature_type(int signature_type, monero_message_signature_type& sig_type) noexcept {
  if (signature_type == MONERO_MESSAGE_SIGN_WITH_SPEND_KEY) {
    sig_type = monero_message_signature_type::SIGN_WITH_SPEND_KEY;
  } else if (signature_type == MONERO_MESSAGE_SIGN_WITH_VIEW_KEY) {
    sig_type = monero_message_signature_type::SIGN_WITH_VIEW_KEY;
  } else {
    return false;
  }

  return true;
}


#ifdef __cplusplus
extern "C"
{
#endif

// --------------------------------- API ERROR ---------------------------------

const char* monero_get_error() noexcept {
  if (last_error.empty()) {
    return "";
  }
  const std::string::size_type size = last_error.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, last_error.c_str(), size + 1);
  last_error.clear();
  return buffer;
}

// --------------------------------- UTILS ---------------------------------

void monero_utils_set_log_level(int level) noexcept {
  DEBUG_START()
  monero_utils::set_log_level(level);
  DEBUG_END()
}

void monero_utils_configure_logging(const char* path, bool console) noexcept {
  DEBUG_START()
  monero_utils::configure_logging(std::string(path), console);
  DEBUG_END()
}

void* monero_utils_get_integrated_address(int network_type, const char* standard_address, const char* payment_id) noexcept {
  DEBUG_START()
  if (standard_address == nullptr) {
    return nullptr;
  }

  monero_network_type net_type;

  if (!parse_network_type(network_type, net_type)) {
    return nullptr;
  }

  monero_integrated_address integrated_address = monero_utils::get_integrated_address(net_type, std::string(standard_address), payment_id != nullptr ? std::string(payment_id) : "");
  monero_integrated_address* ptr = new monero_integrated_address(integrated_address);
  return reinterpret_cast<void*>(ptr);
  DEBUG_END()
  return nullptr;
}

bool monero_utils_is_valid_address(const char* address, int network_type) noexcept {
  DEBUG_START()
  if (address == nullptr) {
    return false;
  }

  monero_network_type net_type;

  if (!parse_network_type(network_type, net_type)) {
    return false;
  }

  return monero_utils::is_valid_address(std::string(address), net_type);
  DEBUG_END()
  return false;
}

bool monero_utils_is_valid_private_view_key(const char* private_view_key) noexcept {
  DEBUG_START()
  if (private_view_key == nullptr) {
    return false;
  }

  return monero_utils::is_valid_private_view_key(std::string(private_view_key));
  DEBUG_END()
  return false;
}

bool monero_utils_is_valid_private_spend_key(const char* private_spend_key) noexcept {
  DEBUG_START()
  if (private_spend_key == nullptr) {
    return false;
  }

  return monero_utils::is_valid_private_spend_key(std::string(private_spend_key));
  DEBUG_END()
  return false;
}

bool monero_utils_is_valid_public_view_key(const char* public_view_key) noexcept {
  DEBUG_START()
  if (public_view_key == nullptr) {
    return false;
  }

  return monero_utils::is_valid_private_view_key(std::string(public_view_key));
  DEBUG_END()
  return false;
}

bool monero_utils_is_valid_public_spend_key(const char* public_spend_key) noexcept {
  DEBUG_START()
  if (public_spend_key == nullptr) {
    return false;
  }

  return monero_utils::is_valid_private_spend_key(std::string(public_spend_key));
  DEBUG_END()
  return false;
}

bool monero_utils_is_valid_language(const char* language) noexcept {
  DEBUG_START()
  if (language == nullptr) {
    return false;
  }

  return monero_utils::is_valid_language(std::string(language));
  DEBUG_END()
  return false;
}

const char* monero_utils_json_to_binary(const char* json) noexcept {
  DEBUG_START()
  if (json == nullptr) {
    return nullptr;
  }

  std::string bin;
  std::string json_str = std::string(json);
  monero_utils::json_to_binary(json_str, bin);
  bin = to_hex(bin);
  const std::string::size_type size = bin.length();
  char *buffer = new char[size];
  memcpy(buffer, bin.data(), size);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_utils_binary_to_json(const char* bin) noexcept {
  DEBUG_START()
  if (bin == nullptr) {
    return nullptr;
  }

  std::string json;
  std::string bin_str = from_hex(std::string(bin));
  monero_utils::binary_to_json(bin_str, json);
  const std::string::size_type size = json.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, json.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_utils_binary_blocks_to_json(const char* bin) noexcept {
  DEBUG_START()
  if (bin == nullptr) {
    return nullptr;
  }

  std::string json;
  std::string bin_str = from_hex(std::string(bin));
  monero_utils::binary_blocks_to_json(bin_str, json);
  const std::string::size_type size = json.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, json.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

// --------------------------------- WALLET INTERFACE ---------------------------------

bool monero_wallet_is_view_only(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    return false;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->is_view_only();
  DEBUG_END()
  return false;
}

void monero_wallet_set_daemon_connection(void* wallet, const char* uri, const char* username, const char* password) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }

  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  if (username == nullptr || password == nullptr) {
    w->set_daemon_connection(std::string(uri != nullptr ? uri : ""));
  } else {
    w->set_daemon_connection(std::string(uri != nullptr ? uri : ""), std::string(username), std::string(password));
  }
  DEBUG_END()
}

const char* monero_wallet_get_daemon_connection(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  boost::optional<monero_rpc_connection> connection = w->get_daemon_connection();
  if (connection == boost::none) {
    return nullptr;
  }
  std::string result = connection->serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

bool monero_wallet_is_connected_to_daemon(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return false;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->is_connected_to_daemon();
  DEBUG_END()
  return false;
}

bool monero_wallet_is_daemon_synced(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return false;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->is_daemon_synced();
  DEBUG_END()
  return false;
}

bool monero_wallet_is_daemon_trusted(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return false;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->is_daemon_trusted();
  DEBUG_END()
  return false;
}

bool monero_wallet_is_synced(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return false;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->is_synced();
  DEBUG_END()
  return false;
}

const char* monero_wallet_get_version(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero_version version = w->get_version();
  std::string result = version.serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

const char* monero_wallet_get_path(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string path = w->get_path();
  const std::string::size_type size = path.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, path.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

int monero_wallet_get_network_type(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return -1;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero_network_type net_type = w->get_network_type();
  return static_cast<int>(net_type);
  DEBUG_END()
  return -1;
}

const char* monero_wallet_get_seed(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string seed = w->get_seed();
  const std::string::size_type size = seed.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, seed.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

const char* monero_wallet_get_seed_language(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string seed_language = w->get_seed_language();
  const std::string::size_type size = seed_language.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, seed_language.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

const char* monero_wallet_get_public_view_key(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string public_view_key = w->get_public_view_key();
  const std::string::size_type size = public_view_key.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, public_view_key.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

const char* monero_wallet_get_public_spend_key(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string public_spend_key = w->get_public_spend_key();
  const std::string::size_type size = public_spend_key.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, public_spend_key.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

const char* monero_wallet_get_private_view_key(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string private_view_key = w->get_private_view_key();
  const std::string::size_type size = private_view_key.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, private_view_key.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

const char* monero_wallet_get_private_spend_key(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string private_spend_key = w->get_private_spend_key();
  const std::string::size_type size = private_spend_key.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, private_spend_key.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

const char* monero_wallet_get_primary_address(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string primary_address = w->get_primary_address();
  const std::string::size_type size = primary_address.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, primary_address.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

const char* monero_wallet_get_address(void* wallet, uint32_t account_idx, uint32_t subaddress_idx) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string address = w->get_address(account_idx, subaddress_idx);
  const std::string::size_type size = address.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, address.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

const char* monero_wallet_get_address_index(void* wallet, const char* address) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  if (address == nullptr) {
    last_error = "Address is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  boost::optional<monero_subaddress> index = w->get_address_index(std::string(address));
  if (index == boost::none) {
    return nullptr;
  }
  std::string result = index->serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

const char* monero_wallet_get_integrated_address(void* wallet, const char* standard_address, const char* payment_id) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  if (standard_address == nullptr) {
    last_error = "Standard address is null";
    return "";
  }
  if (payment_id == nullptr) {
    last_error = "Payment id is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero_integrated_address integrated_address = w->get_integrated_address(std::string(standard_address), std::string(payment_id));
  std::string result = integrated_address.serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

const char* monero_wallet_decode_integrated_address(void* wallet, const char* integrated_address) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  if (integrated_address == nullptr) {
    last_error = "Integrated address is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero_integrated_address decoded_address = w->decode_integrated_address(std::string(integrated_address));
  std::string result = decoded_address.serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

uint64_t monero_wallet_get_height(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return 0;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->get_height();
  DEBUG_END()
  return 0;
}

uint64_t monero_wallet_get_restore_height(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return 0;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->get_restore_height();
  DEBUG_END()
  return 0;
}

void monero_wallet_set_restore_height(void* wallet, uint64_t restore_height) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->set_restore_height(restore_height);
  DEBUG_END()
}

uint64_t monero_wallet_get_daemon_height(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return 0;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->get_daemon_height();
  DEBUG_END()
  return 0;
}

uint64_t monero_wallet_get_daemon_max_peer_height(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return 0;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->get_daemon_max_peer_height();
  DEBUG_END()
  return 0;
}

uint64_t monero_wallet_get_height_by_date(void* wallet, uint16_t year, uint8_t month, uint8_t day) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return 0;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->get_height_by_date(year, month, day);
  DEBUG_END()
  return 0;
}

void monero_wallet_add_listener(void* wallet, void* listener) noexcept {
  DEBUG_START()
  if (wallet == nullptr || listener == nullptr) {
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero::monero_wallet_listener* l = reinterpret_cast<monero::monero_wallet_listener*>(listener);
  w->add_listener(*l);
  DEBUG_END()
}

void monero_wallet_remove_listener(void* wallet, void* listener) noexcept {
  DEBUG_START()
  if (wallet == nullptr || listener == nullptr) {
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero::monero_wallet_listener* l = reinterpret_cast<monero::monero_wallet_listener*>(listener);
  w->remove_listener(*l);
  DEBUG_END()
}

const char* monero_wallet_sync(void* wallet, uint64_t start_height, void* listener) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero::monero_wallet_listener* l = nullptr;
  if (listener != nullptr) {
    l = reinterpret_cast<monero::monero_wallet_listener*>(listener);
  }
  std::string result = w->sync(start_height, *l).serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

void monero_wallet_start_syncing(void* wallet, uint64_t start_height) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->start_syncing(start_height);
  DEBUG_END()
}

void monero_wallet_rescan_spent(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->rescan_spent();
  DEBUG_END()
}

void monero_wallet_rescan_blockchain(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->rescan_blockchain();
  DEBUG_END()
}

uint64_t monero_wallet_get_balance(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return 0;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->get_balance();
  DEBUG_END()
  return 0;
}

uint64_t monero_wallet_get_unlocked_balance(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return 0;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->get_unlocked_balance();
  DEBUG_END()
  return 0;
}

uint64_t monero_wallet_get_account_balance(void* wallet, uint32_t account_idx) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return 0;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->get_balance(account_idx);
  DEBUG_END()
  return 0;
}

uint64_t monero_wallet_get_account_unlocked_balance(void* wallet, uint32_t account_idx) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return 0;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->get_unlocked_balance(account_idx);
  DEBUG_END()
  return 0;
}

uint64_t monero_wallet_get_subaddress_balance(void* wallet, uint32_t account_idx, uint32_t subaddress_idx) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return 0;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->get_balance(account_idx, subaddress_idx);
  DEBUG_END()
  return 0;
}

uint64_t monero_wallet_get_subaddress_unlocked_balance(void* wallet, uint32_t account_idx, uint32_t subaddress_idx) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return 0;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->get_unlocked_balance(account_idx, subaddress_idx);
  DEBUG_END()
  return 0;
}

const char* monero_wallet_get_accounts(void* wallet, bool include_subaddresses) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::vector<monero_account> accounts = w->get_accounts(include_subaddresses);
  std::vector<std::string> serialized_accounts;
  for (const auto& account : accounts) {
    serialized_accounts.push_back(account.serialize());
  }
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("accounts", monero_utils::to_rapidjson_val(doc.GetAllocator(), serialized_accounts), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_get_accounts_by_tag(void* wallet, const char* tag, bool include_subaddresses) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (tag == nullptr) {
    last_error = "Tag is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::vector<monero_account> accounts = w->get_accounts(include_subaddresses, std::string(tag));
  std::vector<std::string> serialized_accounts;
  for (const auto& account : accounts) {
    serialized_accounts.push_back(account.serialize());
  }
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("accounts", monero_utils::to_rapidjson_val(doc.GetAllocator(), serialized_accounts), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_get_account(void* wallet, uint32_t account_idx, bool include_subaddresses) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  boost::optional<monero_account> account = w->get_account(account_idx, include_subaddresses);
  if (account == boost::none) {
    return nullptr;
  }
  std::string result = account->serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_create_account(void* wallet, const char* label) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero_account account = w->create_account(label != nullptr ? std::string(label) : "");
  std::string result = account.serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_get_subaddresses(void* wallet, uint32_t account_idx, const char* subaddress_indices) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::vector<uint32_t> indices;
  if (subaddress_indices != nullptr) {
    rapidjson::Document doc;
    if (doc.Parse(subaddress_indices).HasParseError()) {
      last_error = "Failed to parse subaddress indices";
      return nullptr;
    }
    if (!doc.IsArray()) {
      last_error = "Subaddress indices is not an array";
      return nullptr;
    }
    for (const auto& v : doc.GetArray()) {
      if (!v.IsUint()) {
        last_error = "Subaddress index is not an unsigned integer";
        return nullptr;
      }
      indices.push_back(v.GetUint());
    }
  }
  std::vector<monero_subaddress> subaddresses = w->get_subaddresses(account_idx, indices);
  std::vector<std::string> serialized_subaddresses;
  for (const auto& subaddress : subaddresses) {
    serialized_subaddresses.push_back(subaddress.serialize());
  }
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("subaddresses", monero_utils::to_rapidjson_val(doc.GetAllocator(), serialized_subaddresses), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_get_subaddress(void* wallet, uint32_t account_idx, uint32_t subaddress_idx) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  boost::optional<monero_subaddress> subaddress = w->get_subaddress(account_idx, subaddress_idx);
  if (subaddress == boost::none) {
    return nullptr;
  }
  std::string result = subaddress->serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_create_subaddress(void* wallet, uint32_t account_idx, const char* label) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero_subaddress subaddress = w->create_subaddress(account_idx, label != nullptr ? std::string(label) : "");
  std::string result = subaddress.serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

void monero_wallet_set_subaddress_label(void* wallet, uint32_t account_idx, uint32_t subaddress_idx, const char* label) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  if (label == nullptr) {
    last_error = "Label is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->set_subaddress_label(account_idx, subaddress_idx, std::string(label));
  DEBUG_END()
}

const char* monero_wallet_get_txs(void* wallet, const char* query_json) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (query_json == nullptr) {
    last_error = "Query json is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero_tx_query query = *monero_tx_query::deserialize_from_block(std::string(query_json));
  std::vector<std::shared_ptr<monero_tx_wallet>> txs = w->get_txs(query);
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("txs", monero_utils::to_rapidjson_val(doc.GetAllocator(), txs), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_get_transfers(void* wallet, const char* query_json) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (query_json == nullptr) {
    last_error = "Query json is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero_transfer_query query = *monero_transfer_query::deserialize_from_block(std::string(query_json));
  std::vector<std::shared_ptr<monero_transfer>> transfers = w->get_transfers(query);
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("transfers", monero_utils::to_rapidjson_val(doc.GetAllocator(), transfers), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_get_outputs(void* wallet, const char* query_json) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (query_json == nullptr) {
    last_error = "Query json is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero_output_query query = *monero_output_query::deserialize_from_block(std::string(query_json));
  std::vector<std::shared_ptr<monero_output_wallet>> outputs = w->get_outputs(query);
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("outputs", monero_utils::to_rapidjson_val(doc.GetAllocator(), outputs), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_export_outputs(void* wallet, bool all) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string outputs = w->export_outputs(all);
  const std::string::size_type size = outputs.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, outputs.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

int monero_wallet_import_outputs(void* wallet, const char* outputs) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return -1;
  }
  if (outputs == nullptr) {
    last_error = "Outputs is null";
    return -1;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->import_outputs(std::string(outputs));
  DEBUG_END()
  return -1;
}

const char* monero_wallet_export_key_images(void* wallet, bool all) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return "";
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::vector<std::shared_ptr<monero_key_image>> key_images = w->export_key_images(all);
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("key_images", monero_utils::to_rapidjson_val(doc.GetAllocator(), key_images), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

const char* monero_wallet_import_key_images(void* wallet, const char* key_images_json) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (key_images_json == nullptr) {
    last_error = "Key images json is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::vector<std::shared_ptr<monero_key_image>> key_images = monero_key_image::deserialize_key_images(key_images_json);
  std::shared_ptr<monero_key_image_import_result> import_result = w->import_key_images(key_images);
  std::string result = import_result->serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

void monero_wallet_freeze_output(void* wallet, const char* key_image) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  if (key_image == nullptr) {
    last_error = "Key image is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->freeze_output(std::string(key_image));
  DEBUG_END()
}

void monero_wallet_thaw_output(void* wallet, const char* key_image) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  if (key_image == nullptr) {
    last_error = "Key image is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->thaw_output(std::string(key_image));
  DEBUG_END()
}

bool monero_wallet_is_output_frozen(void* wallet, const char* key_image) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return false;
  }
  if (key_image == nullptr) {
    last_error = "Key image is null";
    return false;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->is_output_frozen(std::string(key_image));
  DEBUG_END()
  return false;
}

int monero_wallet_get_default_fee_priority(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return -1;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return static_cast<int>(w->get_default_fee_priority());
  DEBUG_END()
  return -1;
}

const char* monero_wallet_create_tx(void* wallet, const char* config_json) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (config_json == nullptr) {
    last_error = "Config json is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero_tx_config config = *monero_tx_config::deserialize(std::string(config_json));
  std::shared_ptr<monero_tx_wallet> tx = w->create_tx(config);
  std::string result = tx->serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_create_txs(void* wallet, const char* config_json) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (config_json == nullptr) {
    last_error = "Config json is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  monero_tx_config config = *monero_tx_config::deserialize(std::string(config_json));
  std::vector<std::shared_ptr<monero_tx_wallet>> txs = w->create_txs(config);
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("txs", monero_utils::to_rapidjson_val(doc.GetAllocator(), txs), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_sweep_unlocked(void* wallet, const char* config_json) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (config_json == nullptr) {
    last_error = "Config is null";
    return nullptr;
  }

  monero_wallet* w = reinterpret_cast<monero_wallet*>(wallet);
  monero_tx_config config = *monero_tx_config::deserialize(config_json);
  std::vector<std::shared_ptr<monero_tx_wallet>> txs = w->sweep_unlocked(config);
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("txs", monero_utils::to_rapidjson_val(doc.GetAllocator(), txs), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_sweep_output(void* wallet, const char* config_json) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (config_json == nullptr) {
    last_error = "Config is null";
    return nullptr;
  }

  monero_wallet* w = reinterpret_cast<monero_wallet*>(wallet);
  monero_tx_config config = *monero_tx_config::deserialize(config_json);
  std::shared_ptr<monero_tx_wallet> tx = w->sweep_output(config);
  std::string result = tx->serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_sweep_dust(void* wallet, bool relay) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }

  monero_wallet* w = reinterpret_cast<monero_wallet*>(wallet);
  std::vector<std::shared_ptr<monero_tx_wallet>> txs = w->sweep_dust(relay);
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("txs", monero_utils::to_rapidjson_val(doc.GetAllocator(), txs), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END();
  return nullptr;
}

const char* monero_wallet_relay_tx(void* wallet, const char* tx_metadata) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (tx_metadata == nullptr) {
    last_error = "Tx metadata is null";
    return nullptr;
  }

  monero_wallet* w = reinterpret_cast<monero_wallet*>(wallet);
  std::string tx_hash = w->relay_tx(tx_metadata);
  const std::string::size_type size = tx_hash.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, tx_hash.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_describe_tx_set(void* wallet, const char* tx_set_json) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (tx_set_json == nullptr) {
    last_error = "Tx set is null";
    return nullptr;
  }

  monero_tx_set tx_set = monero_tx_set::deserialize(tx_set_json);
  monero_wallet* w = reinterpret_cast<monero_wallet*>(wallet);
  std::string result = w->describe_tx_set(tx_set).serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_sign_txs(void* wallet, const char* unsigned_tx_hex) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (unsigned_tx_hex == nullptr) {
    last_error = "Unsigned tx hex is null";
    return nullptr;
  }

  monero_wallet* w = reinterpret_cast<monero_wallet*>(wallet);
  std::string result = w->sign_txs(unsigned_tx_hex).serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

void monero_wallet_stop_syncing(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->stop_syncing();
  DEBUG_END()
}

void monero_wallet_scan_txs(void* wallet, const char* tx_hashes) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  if (tx_hashes == nullptr) {
    last_error = "Tx hashes are null";
    return;
  }

  std::string _tx_hashes(tx_hashes);
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::istringstream iss = _tx_hashes.empty() ? std::istringstream() : std::istringstream(_tx_hashes);
  boost::property_tree::ptree node;
  boost::property_tree::read_json(iss, node);
  std::vector<std::string> hashes;

  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
    std::string key = it->first;
    if (key == std::string("txHashes")) {
      for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
        hashes.push_back(it2->second.data());
      }
    }
  }

  w->scan_txs(hashes);
  DEBUG_END()
}

const char* monero_wallet_submit_txs(void* wallet, const char* signed_tx_hex) noexcept{
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (signed_tx_hex == nullptr) {
    last_error = "Signed tx hex is null";
    return nullptr;
  }

  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _signed_tx_hex = std::string(signed_tx_hex);
  std::vector<std::string> txs = w->submit_txs(_signed_tx_hex);
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("txs", monero_utils::to_rapidjson_val(doc.GetAllocator(), txs), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_sign_message(void* wallet, const char* msg, int signature_type, uint32_t account_idx, uint32_t subaddress_idx) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _msg = msg != nullptr ? std::string(msg) : std::string("");
  monero_message_signature_type _sig_type;

  if (!parse_message_signature_type(signature_type, _sig_type)) {
    last_error = "Invalid signature type";
    return nullptr;
  }

  std::string result = w->sign_message(_msg, _sig_type, account_idx, subaddress_idx);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_verify_message(void* wallet, const char* msg, const char* address, const char* signature) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _msg = msg != nullptr ? std::string(msg) : std::string("");
  std::string _address = address != nullptr ? std::string(address) : std::string("");
  std::string _signature = signature != nullptr ? std::string(signature) : std::string("");
  std::string result = w->verify_message(_msg, _address, _signature).serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_get_tx_key(void* wallet, const char* tx_hash) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _tx_hash = tx_hash != nullptr ? std::string(tx_hash) : std::string("");
  std::string result = w->get_tx_key(_tx_hash);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_check_tx_key(void* wallet, const char* tx_hash, const char* tx_key, const char* address) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _tx_hash = tx_hash != nullptr ? std::string(tx_hash) : std::string("");
  std::string _tx_key = tx_key != nullptr ? std::string(tx_key) : std::string("");
  std::string _address = address != nullptr ? std::string(address) : std::string("");
  std::string result = w->check_tx_key(_tx_hash, _tx_key, _address)->serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_get_tx_proof(void* wallet, const char* tx_hash, const char* address, const char* message) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _tx_hash = tx_hash != nullptr ? std::string(tx_hash) : std::string("");
  std::string _address = address != nullptr ? std::string(address) : std::string("");
  std::string _message = message != nullptr ? std::string(message) : std::string("");
  std::string result = w->get_tx_proof(_tx_hash, _address, _message);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_check_tx_proof(void* wallet, const char* tx_hash, const char* address, const char* message, const char* signature) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _tx_hash = tx_hash != nullptr ? std::string(tx_hash) : std::string("");
  std::string _address = address != nullptr ? std::string(address) : std::string("");
  std::string _message = message != nullptr ? std::string(message) : std::string("");
  std::string _signature = signature != nullptr ? std::string(signature) : std::string("");
  std::string result = w->check_tx_proof(_tx_hash, _address, _message, _signature)->serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_get_spend_proof(void* wallet, const char* tx_hash, const char* message) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _tx_hash = tx_hash != nullptr ? std::string(tx_hash) : std::string("");
  std::string _message = message != nullptr ? std::string(message) : std::string("");
  std::string result = w->get_spend_proof(_tx_hash, _message);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

bool monero_wallet_check_spend_proof(void* wallet, const char* tx_hash, const char* message, const char* signature) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return false;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _tx_hash = tx_hash != nullptr ? std::string(tx_hash) : std::string("");
  std::string _message = message != nullptr ? std::string(message) : std::string("");
  std::string _signature = signature != nullptr ? std::string(signature) : std::string("");
  return w->check_spend_proof(_tx_hash, _message, _signature);
  DEBUG_END()
  return false;
}

const char* monero_wallet_get_reserve_proof_wallet(void* wallet, const char* message) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _message = message != nullptr ? std::string(message) : std::string("");
  std::string result = w->get_reserve_proof_wallet(_message);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_get_reserve_proof_account(void* wallet, uint32_t account_idx, uint64_t amount, const char* message) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _message = message != nullptr ? std::string(message) : std::string("");
  std::string result = w->get_reserve_proof_account(account_idx, amount, _message);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_check_reserve_proof(void* wallet, const char* address, const char* message, const char* signature) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _address = address != nullptr ? std::string(address) : std::string("");
  std::string _message = message != nullptr ? std::string(message) : std::string("");
  std::string _signature = message != nullptr ? std::string(signature) : std::string("");
  std::string result = w->check_reserve_proof(_address, _message, _signature)->serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_get_tx_note(void* wallet, const char* tx_hash) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _tx_hash = tx_hash != nullptr ? std::string(tx_hash) : std::string("");
  std::string result = w->get_tx_note(_tx_hash);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

void monero_wallet_set_tx_note(void* wallet, const char* tx_hash, const char* note) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _tx_hash = tx_hash != nullptr ? std::string(tx_hash) : std::string("");
  std::string _note = note != nullptr ? std::string(note) : std::string("");
  w->set_tx_note(_tx_hash, _note);
  DEBUG_END()
}

const char* monero_wallet_get_tx_notes(void* wallet, const char* tx_hashes) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (tx_hashes == nullptr) {
    last_error = "Tx hashes are null";
    return nullptr;
  }

  std::string _tx_hashes(tx_hashes);
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::istringstream iss = _tx_hashes.empty() ? std::istringstream() : std::istringstream(_tx_hashes);
  boost::property_tree::ptree node;
  boost::property_tree::read_json(iss, node);
  std::vector<std::string> hashes;

  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
    std::string key = it->first;
    if (key == std::string("txHashes")) {
      for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
        hashes.push_back(it2->second.data());
      }
    }
  }

  std::vector<std::string> notes = w->get_tx_notes(hashes);
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("txNotes", monero_utils::to_rapidjson_val(doc.GetAllocator(), notes), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

uint64_t monero_wallet_add_address_book_entry(void* wallet, const char* address, const char* description) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return 0;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _address = address != nullptr ? std::string(address) : std::string("");
  std::string _description = description != nullptr ? std::string(description) : std::string("");
  return w->add_address_book_entry(_address, _description);
  DEBUG_END()
  return 0;
}

void monero_wallet_edit_address_book_entry(void* wallet, uint64_t index, bool set_address, const char* address, bool set_description, const char* description) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _address = address != nullptr ? std::string(address) : std::string("");
  std::string _description = description != nullptr ? std::string(description) : std::string("");
  w->edit_address_book_entry(index, set_address, _address, set_description, _description);
  DEBUG_END()
}

void monero_wallet_delete_address_book_entry(void* wallet, uint64_t index) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->delete_address_book_entry(index);
  DEBUG_END()
}

const char* monero_wallet_get_payment_uri(void* wallet, const char* config) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::shared_ptr<monero_tx_config> tx_config = monero_tx_config::deserialize(config);
  std::string result = w->get_payment_uri(*tx_config);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_parse_payment_uri(void* wallet, const char* uri) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (uri == nullptr) {
    last_error = "Uri is null";
    return nullptr;
  }

  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string result = w->parse_payment_uri(std::string(uri))->serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_get_attribute(void* wallet, const char* key) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (key == nullptr) {
    last_error = "Key is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string value;

  if (!w->get_attribute(std::string(key), value)) {
    last_error = "Failed to get attribute";
    return nullptr;
  }

  const std::string::size_type size = value.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, value.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

void monero_wallet_set_attribute(void* wallet, const char* key, const char* value) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  if (key == nullptr) {
    last_error = "Key is null";
    return;
  }
  if (value == nullptr) {
    last_error = "Value is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->set_attribute(std::string(key), std::string(value));
  DEBUG_END()
}

void monero_wallet_start_mining(void* wallet, uint32_t threads, bool background_mining, bool ignore_battery) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->start_mining(threads, background_mining, ignore_battery);
  DEBUG_END()
}

void monero_wallet_stop_mining(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->stop_mining();
  DEBUG_END()
}

void monero_wallet_wait_for_next_block(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->wait_for_next_block();
  DEBUG_END()
}

bool monero_wallet_is_multisig_import_needed(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return false;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->is_multisig_import_needed();
  DEBUG_END()
  return false;
}

bool monero_wallet_is_multisig(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return false;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  return w->is_multisig();
  DEBUG_END()
  return false;
}

const char* monero_wallet_get_multisig_info(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string result = w->get_multisig_info().serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_prepare_multisig(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string result = w->prepare_multisig();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_make_multisig(void* wallet, const char* multisig_hexes, int threshold, const char* password) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (multisig_hexes == nullptr) {
    last_error = "Multisig hexes are null";
    return nullptr;
  }

  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _multisig_hexes(multisig_hexes);
  std::istringstream iss = _multisig_hexes.empty() ? std::istringstream() : std::istringstream(_multisig_hexes);
  boost::property_tree::ptree node;
  boost::property_tree::read_json(iss, node);
  std::vector<std::string> hexes;

  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
    std::string key = it->first;
    if (key == std::string("multisigHexes")) {
      for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
        hexes.push_back(it2->second.data());
      }
    }
  }
  std::string _password = password == nullptr ? std::string("") : std::string(password);
  std::string result = w->make_multisig(hexes, threshold, _password);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_exchange_multisig_keys(void* wallet, const char* multisig_hexes, const char* password) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (multisig_hexes == nullptr) {
    last_error = "Multisig hexes are null";
    return nullptr;
  }

  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _multisig_hexes(multisig_hexes);
  std::istringstream iss = _multisig_hexes.empty() ? std::istringstream() : std::istringstream(_multisig_hexes);
  boost::property_tree::ptree node;
  boost::property_tree::read_json(iss, node);
  std::vector<std::string> hexes;

  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
    std::string key = it->first;
    if (key == std::string("multisigHexes")) {
      for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
        hexes.push_back(it2->second.data());
      }
    }
  }
  std::string _password = password == nullptr ? std::string("") : std::string(password);
  std::string result = w->exchange_multisig_keys(hexes, _password).serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

int monero_wallet_import_multisig_hex(void* wallet, const char* multisig_hexes) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return -1;
  }
  if (multisig_hexes == nullptr) {
    last_error = "Multisig hexes are null";
    return -1;
  }

  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string _multisig_hexes(multisig_hexes);
  std::istringstream iss = _multisig_hexes.empty() ? std::istringstream() : std::istringstream(_multisig_hexes);
  boost::property_tree::ptree node;
  boost::property_tree::read_json(iss, node);
  std::vector<std::string> hexes;

  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
    std::string key = it->first;
    if (key == std::string("multisigHexes")) {
      for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
        hexes.push_back(it2->second.data());
      }
    }
  }
  return w->import_multisig_hex(hexes);
  DEBUG_END()
  return -1;
}

const char* monero_wallet_export_multisig_hex(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string result = w->export_multisig_hex();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_sign_multisig_tx_hex(void* wallet, const char* multisig_tx_hex) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::string result = w->sign_multisig_tx_hex(std::string(multisig_tx_hex)).serialize();
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_submit_multisig_tx_hex(void* wallet, const char* signed_multisig_tx_hex) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return nullptr;
  }
  if (signed_multisig_tx_hex == nullptr) {
    last_error = "Signed multisig tx hex is null";
    return nullptr;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  std::vector<std::string> hex = w->submit_multisig_tx_hex(std::string(signed_multisig_tx_hex));
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("tx_hashes", monero_utils::to_rapidjson_val(doc.GetAllocator(), hex), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

void monero_wallet_change_password(void* wallet, const char* old_password, const char* new_password) noexcept {
  DEBUG_START()
  if (wallet == nullptr || old_password == nullptr || new_password == nullptr) {
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->change_password(std::string(old_password), std::string(new_password));
  DEBUG_END()
}

void monero_wallet_move_to(void* wallet, const char* path, const char* password) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  if (path == nullptr) {
    last_error = "Path is null";
    return;
  }

  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->move_to(std::string(path), password != nullptr ? std::string(password) : std::string(""));
  DEBUG_END()
}

void monero_wallet_save(void* wallet) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->save();
  DEBUG_END()
}

void monero_wallet_close(void* wallet, bool save) noexcept {
  DEBUG_START()
  if (wallet == nullptr) {
    last_error = "Wallet is null";
    return;
  }
  monero::monero_wallet* w = reinterpret_cast<monero::monero_wallet*>(wallet);
  w->close(save);
  DEBUG_END()
}

// --------------------------------- FULL WALLET ---------------------------------

bool monero_wallet_full_wallet_exists(const char* path) noexcept {
  DEBUG_START()
  if (path == nullptr) {
    return false;
  }

  return monero::monero_wallet_full::wallet_exists(std::string(path));
  DEBUG_END()
  return false;
}

void* monero_wallet_full_open_wallet(const char* path, const char* password, int network_type) noexcept {
  DEBUG_START()
  if (path == nullptr) {
    last_error = "Path is null";
    return nullptr;
  }
  monero_network_type net_type;

  if (!parse_network_type(network_type, net_type)) {
    last_error = "Invalid network type";
    return nullptr;
  }

  monero::monero_wallet_full* w = monero::monero_wallet_full::open_wallet(std::string(path), password != nullptr ? std::string(password) : "", net_type);
  return reinterpret_cast<void*>(w);
  DEBUG_END()
  return nullptr;
}

void* monero_wallet_full_create_wallet(const char* config) noexcept {
  DEBUG_START()
  if (config == nullptr) {
    last_error = "Config is null";
    return nullptr;
  }
  monero_wallet_config wallet_config = *monero_wallet_config::deserialize(config);
  monero::monero_wallet_full* w = monero::monero_wallet_full::create_wallet(wallet_config);
  return reinterpret_cast<void*>(w);
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_full_get_seed_languages() noexcept {
  DEBUG_START()
  std::vector<std::string> languages = monero::monero_wallet_full::get_seed_languages();
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("languages", monero_utils::to_rapidjson_val(doc.GetAllocator(), languages), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return "";
}

// --------------------------------- KEYS-ONLY WALLET ---------------------------------

void* monero_wallet_keys_create_wallet_from_keys(const char* config) noexcept {
  DEBUG_START()
  if (config == nullptr) {
    last_error = "Config is null";
    return nullptr;
  }
  monero_wallet_config wallet_config = *monero_wallet_config::deserialize(config);
  monero::monero_wallet_keys* w = monero::monero_wallet_keys::create_wallet_from_keys(wallet_config);
  return reinterpret_cast<void*>(w);
  DEBUG_END()
  return nullptr;
}

void* monero_wallet_keys_create_wallet_from_seed(const char* config) noexcept {
  DEBUG_START()
  if (config == nullptr) {
    last_error = "Config is null";
    return nullptr;
  }
  monero_wallet_config wallet_config = *monero_wallet_config::deserialize(config);
  monero::monero_wallet_keys* w = monero::monero_wallet_keys::create_wallet_from_seed(wallet_config);
  return reinterpret_cast<void*>(w);
  DEBUG_END()
  return nullptr;
}

void* monero_wallet_keys_create_wallet_random(const char* config) noexcept {
  DEBUG_START()
  if (config == nullptr) {
    last_error = "Config is null";
    return nullptr;
  }
  monero_wallet_config wallet_config = *monero_wallet_config::deserialize(config);
  monero::monero_wallet_keys* w = monero::monero_wallet_keys::create_wallet_random(wallet_config);
  return reinterpret_cast<void*>(w);
  DEBUG_END()
  return nullptr;
}

const char* monero_wallet_keys_get_seed_languages() noexcept {
  DEBUG_START()
  std::vector<std::string> languages = monero::monero_wallet_keys::get_seed_languages();
  rapidjson::Document doc;
  rapidjson::Value root(rapidjson::kObjectType);
  doc.SetObject();
  root.AddMember("languages", monero_utils::to_rapidjson_val(doc.GetAllocator(), languages), doc.GetAllocator());
  root.Swap(doc);
  std::string result = monero_utils::serialize(doc);
  const std::string::size_type size = result.size();
  char *buffer = new char[size + 1];
  memcpy(buffer, result.c_str(), size + 1);
  return buffer;
  DEBUG_END()
  return nullptr;
}

#ifdef __cplusplus
}
#endif
