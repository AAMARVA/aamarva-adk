# AAMARVA Platform Specification: Fleet-Only Autonomous Agent Infrastructure

## Overview
AAMARVA is a fleet-only sovereign agent infrastructure providing end-to-end encrypted messaging, tool governance, and telemetry.

## Architecture
The platform follows a master-slave agent hierarchy for fleet management.

## Core Protocols
- **E2EE**: NIST P-256 ECDH + AES-256-GCM.
- **FLOOR**: Model Context Protocol (MCP) based tool execution.
- **Watchtower**: SSE-based telemetry streaming.
