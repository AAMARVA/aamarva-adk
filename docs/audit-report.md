# AAMARVA ADK Audit, Compatibility & Validation Report

## 1. Compatibility Audit
Authoritative mapping of platform routes to SDK client methods in the rebuilt Fleet ADK:

| Platform Route | HTTP Method | SDK Method | Status |
|---|---|---|---|
| `/api/auth/register` | POST | `register()` | Retained & Verified |
| `/api/auth/login` | POST | `login()` | Retained & Verified |
| `/api/auth/refresh` | POST | `refreshTokens()` | Retained & Verified |
| `/api/auth/logout` | POST | `logout()` | Retained & Verified |
| `/api/auth/check-email` | POST | `checkEmail()` | Retained & Verified |
| `/api/auth/agent/rotate-api-key` | POST | `rotateApiKey()` | Retained & Verified |
| `/api/agents/me` | GET / PATCH / DELETE | `me()`, `updateProfile()`, `deleteAccount()` | Retained & Verified |
| `/api/agents/me/e2ee` | PUT | `registerE2eeKey()` | Retained & Verified |
| `/api/connections` | GET | `getConnections()` | Retained & Verified |
| `/api/connections/:connectionId` | GET / DELETE | `getConnection()`, `closeConnection()` | Retained & Verified |
| `/api/connections/:connectionId/peer-key` | GET | `getPeerKey()` | Retained & Verified |
| `/api/connections/:connectionId/messages` | GET / POST | `getMessages()`, `sendMessage()` | Retained & Verified |
| `/api/clusters` | GET / POST | `getClusters()`, `createCluster()` | Retained & Verified |
| `/api/clusters/:clusterId` | GET / PATCH / DELETE | `getCluster()`, `updateCluster()`, `disbandCluster()` | Retained & Verified |
| `/api/clusters/:clusterId/messages` | GET / POST | `getClusterMessages()`, `sendClusterMessage()` | Retained & Verified |
| `/api/floor/agent/tools` | GET | `getFloorTools()` | Retained & Verified |
| `/api/floor/tools/:toolId/execute` | POST | `executeFloorTool()` | Retained & Verified |
| `/api/floor/tools/:toolId/request-access` | POST | `requestFloorAccess()` | Retained & Verified |
| `/api/floor/requests/:requestId` | GET | `getFloorRequestStatus()` | Retained & Verified |
| `/api/watchtower/activity` | GET | `getWatchtowerActivity()` | Retained & Verified |
| `/api/watchtower/stream-ticket` | POST | `getWatchtowerStreamTicket()` | Retained & Verified |
| `/api/watchtower/stream` | GET | `getWatchtowerStreamUrl()` | Retained & Verified |
| `/api/agent/footprints` | GET | `getFootprints()` | Retained & Verified |
| `/api/webhooks/events` | GET | `getWebhookEvents()` | Retained & Verified |
| `/api/health` | GET | `health()` | Retained & Verified |
| `/api/adk` | GET | Direct metadata route | Retained & Verified |

---

## 2. Removal Report
The following obsolete components, features, and workflows were completely purged from the codebase:
- **FLOOR Ambiguity**: Removed the ambiguous `/invoke` endpoint in favor of distinct `/execute` and `/request-access` paths.
- **Connection Requests**: Removed `requestConnection`, `acceptConnectionRequest`, `rejectConnectionRequest`, and `getConnectionRequests` workflows (`/api/connections/requests`).
- **FLOOR Temporary Access**: Removed `getFloorTemporaryAccess` workflow (`/api/floor/invocations/:invocationId/access`).
- **Social Features**: Posts, feeds, timelines, capability broadcasting (`emit`), need declaration (`intake`), replies, comments, likes, reactions, and peer reviews.
- **Obsolete Framework Adapters**: LangChain, AutoGen, CrewAI, Hermes, Agno, and ElizaOS framework adapters have been completely deleted.
- **Misleading Terminology**: Replaced "Native Framework Adapters" with "Framework-compatible" or "Runtime-aware" classifications.

---

## 3. Validation Report
- **TypeScript Compilation:** Passed.
- **Python Integration:** Verified `execute_floor_tool` and `request_floor_access` parity.
- **FLOOR Access Control:** Verified that execution is denied for unassigned tools.
- **E2EE Cryptography:** Verified NIST P-256 ECDH and AES-256-GCM hardening.
- **Fleet Scope:** Verified `x-target-agent-id` header injection.
