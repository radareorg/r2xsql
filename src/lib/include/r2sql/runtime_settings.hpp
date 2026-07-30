// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <xsql/runtime_settings.hpp>

#include <cstddef>

namespace r2sql {

// r2sql's runtime-settings wrapper over the shared libxsql core. r2sql carries
// only the 8 common keys (query_timeout_ms / queue_admission_timeout_ms /
// max_queue / hints_enabled / the timeout-stack view + the two dispatch-only
// timeout_push/pop verbs) — it adds no tool-specific runtime knobs of its own.
//
// Unlike idasql, the settings are owned PER-Session (not a global singleton):
// r2sql sessions are independent (one per open binary / server), so each keeps
// its own PRAGMA r2sql.* state. The shared core does all the work — this thin
// wrapper only states the timeout-stack cap explicitly and forwards accessors.
class RuntimeSettings {
public:
    RuntimeSettings()
        // Cap the client-driven PRAGMA r2sql.timeout_push stack (matches
        // idasql/bnsql's 64, which is also the shared-core default). Stated
        // explicitly so the bound is visible at the adopter.
        : common_(xsql::runtime::RuntimeSettingsCoreOptions{64}) {}

    int query_timeout_ms() const { return common_.query_timeout_ms(); }

    bool hints_enabled() const { return common_.hints_enabled(); }

    xsql::runtime::RuntimeSettingsCore& common_settings() { return common_; }
    const xsql::runtime::RuntimeSettingsCore& common_settings() const {
        return common_;
    }

private:
    xsql::runtime::RuntimeSettingsCore common_;
};

}  // namespace r2sql
