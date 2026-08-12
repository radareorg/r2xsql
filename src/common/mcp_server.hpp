// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

/**
 * mcp_server.hpp - MCP server wrapper for r2xsql
 *
 * r2xsql::McpServer - SSE-based MCP server exposing a single
 * `r2xsql_query` tool that runs SQL against the host radare2 session.
 *
 * Thread-safe via a command queue pattern. Tool handlers either invoke
 * the query callback directly (use_queue=false, CLI mode) or queue
 * commands for execution on the drainer thread (use_queue=true, used
 * by the in-r2 plugin so MCP-driven queries serialize against manual
 * `sql ...` calls from the r2 prompt).
 *
 * Queue/timeout behavior uses fixed constants (defaults are good enough
 * until r2xsql grows its own settings layer).
 */

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace r2xsql {

// SQL callback for handling requests.
using QueryCallback = std::function<std::string(const std::string& sql)>;

// Internal command structure for cross-thread execution.
struct McpPendingCommand {
    enum class Type { Query };

    Type type = Type::Query;
    std::string input;
    std::string result;
    bool started = false;
    bool canceled = false;
    bool completed = false;
    std::mutex done_mutex;
    std::condition_variable done_cv;
};

struct McpQueueResult {
    bool success;
    std::string payload;
};

class McpServer {
public:
    McpServer();
    ~McpServer();

    // Non-copyable
    McpServer(const McpServer&) = delete;
    McpServer& operator=(const McpServer&) = delete;

    /**
     * Start MCP server on given port with callback.
     *
     * @param port Port to listen on (0 = random port 9000-9999)
     * @param query_cb SQL query callback
     * @param bind_addr Address to bind to (default: localhost only)
     * @param use_queue If true, callbacks are queued for the drainer
     *                  thread (plugin mode with run_until_stopped()).
     *                  If false, callbacks are invoked directly on the
     *                  SSE-handler thread (CLI mode).
     * @return Actual port used, or -1 on failure
     */
    int start(int port, QueryCallback query_cb,
              const std::string& bind_addr = "127.0.0.1", bool use_queue = false);

    /**
     * Block until server stops, processing commands on the calling thread.
     * Only needed when use_queue=true.
     */
    void run_until_stopped();

    /**
     * Stop the server.
     */
    void stop();

    /**
     * Check if server is running.
     */
    bool is_running() const { return running_.load(); }

    /**
     * Get the port the server is listening on.
     */
    int port() const { return port_; }

    /**
     * Get the SSE endpoint URL.
     */
    std::string url() const;

    /**
     * Get bind address configured at startup.
     */
    const std::string& bind_addr() const { return bind_addr_; }

    /**
     * Set interrupt check function (called during wait loop).
     */
    void set_interrupt_check(std::function<bool()> check);

    /**
     * Queue a command for execution on the drainer thread.
     * Called by MCP tool handlers when use_queue=true.
     */
    McpQueueResult queue_and_wait(McpPendingCommand::Type type, const std::string& input);

private:
    std::function<bool()> interrupt_check_;
    std::atomic<bool> running_{false};
    std::atomic<bool> use_queue_{false};
    std::string bind_addr_{"127.0.0.1"};
    int port_{0};

    // Command queue for cross-thread execution.
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::deque<std::shared_ptr<McpPendingCommand>> pending_commands_;

    // Callback stored for execution.
    QueryCallback query_cb_;

    // Forward declaration - impl hides fastmcpp.
    class Impl;
    std::unique_ptr<Impl> impl_;

    void complete_pending_commands(const std::string& result);
};

/**
 * Format MCP server info for display.
 */
std::string format_mcp_info(int port);
std::string format_mcp_info(int port, const std::string& bind_addr);

/**
 * Format MCP server status.
 */
std::string format_mcp_status(int port, bool running);
std::string format_mcp_status(int port, bool running, const std::string& bind_addr);

} // namespace r2xsql
