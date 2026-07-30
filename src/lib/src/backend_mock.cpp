// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
#include <r2sql/backend_mock.hpp>

namespace r2sql {

MockBackend::MockBackend() = default;

void MockBackend::set_response(std::string command, std::string response) {
  std::lock_guard lock(m_);
  sequences_.erase(command);
  canned_[std::move(command)] = std::move(response);
}

void MockBackend::set_responses(std::initializer_list<std::pair<std::string, std::string>> kvs) {
  std::lock_guard lock(m_);
  for (auto& kv : kvs) {
    sequences_.erase(kv.first);
    canned_[kv.first] = kv.second;
  }
}

void MockBackend::set_response_sequence(
    std::string command, std::vector<std::string> responses) {
  std::lock_guard lock(m_);
  canned_.erase(command);
  auto& sequence = sequences_[std::move(command)];
  sequence.clear();
  for (auto& response : responses) sequence.push_back(std::move(response));
}

const std::vector<std::string>& MockBackend::issued_commands() const {
  return issued_;
}

void MockBackend::clear_issued() {
  std::lock_guard lock(m_);
  issued_.clear();
}

std::string MockBackend::cmd(std::string_view command) {
  std::lock_guard lock(m_);
  std::string key(command);
  issued_.push_back(key);
  auto sequence = sequences_.find(key);
  if (sequence != sequences_.end()) {
    if (sequence->second.empty()) return std::string{};
    std::string response = sequence->second.front();
    if (sequence->second.size() > 1) sequence->second.pop_front();
    return response;
  }
  auto it = canned_.find(key);
  if (it == canned_.end()) return std::string{};
  return it->second;
}

std::unique_ptr<Backend> make_mock_backend() {
  return std::make_unique<MockBackend>();
}

}  // namespace r2sql
