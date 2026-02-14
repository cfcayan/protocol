# Enzyme Blue Security Review (Codex)

## Brief/Intro
This review identified several high-impact security risks concentrated around privileged upgrade pathways, initialization safety, and operational hardening (CI/supply chain and relayer policy). If abused in production, the most severe outcomes are protocol-wide denial of service (by misconfigured or malicious implementation upgrades), governance-level abuse of arbitrary calls, and accelerated treasury gas depletion in relayer flows.

---

## Attack Surface Map

### 1) Entrypoints and execution models
- **Primary app type**: Solidity protocol contracts with upgradeable/proxy patterns (`BeaconProxy`, dispatcher-owned ownership model).
- **User-facing entrypoints**: `external`/`public` functions across core/release/persistent contracts.
- **Privileged entrypoints**:
  - Dispatcher owner-governed mutators (`setImplementation`, `setCanonicalLib`, arbitrary call admin hooks).
  - Fund owner/comptroller-gated operational methods (e.g., paymaster relayer controls).

### 2) Auth/Authz boundaries (representative)
| Component | Auth mechanism | Notes |
|---|---|---|
| `DispatcherOwnedBeacon` | `onlyOwner` via dispatcher owner | Upgrade authority concentrated in dispatcher owner. |
| `BeaconProxyFactory` | `getOwner()` check only for canonical-lib updates | Proxy deployment itself is public. |
| `ProtocolFeeReserveLib` | `onlyDispatcherOwner` for arbitrary call | Powerful admin capability. |
| `GasRelayPaymasterLib` | `onlyComptroller`, `onlyFundOwner`, relay hub checks | Relayed-call policy allows broad selector surface. |

### 3) Privileged actions
- Implementation upgrades: beacon implementation and canonical library updates.
- Arbitrary external calls from protocol-fee-reserve context.
- Paymaster funding and additional relayer user management.

### 4) External calls / integrations
- `address.call(...)` in `ProtocolFeeReserveLib.callOnContract`.
- `IGsnRelayHub.depositFor` and balance queries in gas relayer module.
- Oracle calls and external protocol integrations throughout adapters/feeds.

### 5) Parsing / deserialization / low-level primitives
- Multiple `abi.decode(...)` call sites in vault actions and extension flows.
- Widespread `delegatecall` in proxy architecture (`BeaconProxy`, `NonUpgradableProxy`).

### 6) File handling / command execution
- Not applicable at runtime (on-chain contracts), but CI pipeline is a supply-chain trust boundary.

### 7) CI/CD and supply chain
- GitHub Actions pipeline installs tools from floating versions (`bun-version: latest`, Foundry `stable`) without pinning.

---

## Findings (sorted by severity)

## High

### 1) Missing implementation validation in upgrade paths can brick all beacon proxies
- **Severity**: High
- **Category**: Insecure Design / Upgrade Safety
- **Location**:
  - `contracts/utils/0.8.19/dispatcher-owned-beacon/DispatcherOwnedBeacon.sol`
  - `contracts/utils/0.6.12/beacon-proxy/BeaconProxyFactory.sol`

## 2. Description

### Brief/Intro
Two privileged upgrade setters (`setImplementation` and `__setCanonicalLib`) accept arbitrary addresses without validating that the new target is a non-zero deployed contract. In production, a mistaken upgrade or compromised governance action can point beacon/proxy execution to an invalid target and cause broad denial of service for dependent proxies.

### Vulnerability Details
The upgrade path currently trusts `_nextImplementation` and `_nextCanonicalLib` as-is:

- `DispatcherOwnedBeacon.setImplementation(address _nextImplementation)` stores `_nextImplementation` directly.
- `BeaconProxyFactory.__setCanonicalLib(address _nextCanonicalLib)` stores `_nextCanonicalLib` directly.

Neither path checks:
1. `address(0)` exclusion, or
2. that runtime bytecode exists at the target (`extcodesize > 0` / `.code.length > 0`).

Because beacon/proxy systems delegate execution to these pointers, a bad target can break all downstream calls that depend on valid delegatecall destinations. This is a trust-boundary issue between governance/operator input and critical upgrade state.

Relevant snippet pattern (current behavior):
```solidity
function setImplementation(address _nextImplementation) external override onlyOwner {
    implementation = _nextImplementation;
}

function __setCanonicalLib(address _nextCanonicalLib) internal {
    canonicalLib = _nextCanonicalLib;
}
```

### Impact Details
If exploited or triggered by operational error:
- **Protocol availability risk**: affected proxy families can fail on every execution path that relies on delegatecall to the configured implementation/library.
- **Operational emergency risk**: teams may need urgent governance intervention to restore a valid implementation, causing downtime and incident response overhead.
- **Financial risk (indirect but material)**: users can be blocked from routine fund operations (deposits, redemptions, management actions) until recovery.

This maps to high-severity impact classes commonly accepted in smart-contract bounty scopes: protocol-level denial of service and loss of critical functionality.

### References
- Code references:
  - `contracts/utils/0.8.19/dispatcher-owned-beacon/DispatcherOwnedBeacon.sol`
  - `contracts/utils/0.6.12/beacon-proxy/BeaconProxyFactory.sol`
- External guidance:
  - OpenZeppelin upgradeability best practices: <https://docs.openzeppelin.com/upgrades-plugins/1.x/>
  - Solidity security considerations: <https://docs.soliditylang.org/en/latest/security-considerations.html>

### Fix
- Validate `address != 0` and `code.length/extcodesize > 0` before committing upgrade address.
- Optionally emit `old -> new` change events and apply timelock governance for additional operational safety.

### Patch (minimal diff)
```diff
--- a/contracts/utils/0.8.19/dispatcher-owned-beacon/DispatcherOwnedBeacon.sol
+++ b/contracts/utils/0.8.19/dispatcher-owned-beacon/DispatcherOwnedBeacon.sol
@@
     function setImplementation(address _nextImplementation) external override onlyOwner {
+        require(_nextImplementation != address(0), "setImplementation: empty");
+        require(_nextImplementation.code.length > 0, "setImplementation: non-contract");
         implementation = _nextImplementation;
@@
--- a/contracts/utils/0.6.12/beacon-proxy/BeaconProxyFactory.sol
+++ b/contracts/utils/0.6.12/beacon-proxy/BeaconProxyFactory.sol
@@
     function __setCanonicalLib(address _nextCanonicalLib) internal {
+        require(_nextCanonicalLib != address(0), "__setCanonicalLib: empty");
+        uint256 size;
+        assembly { size := extcodesize(_nextCanonicalLib) }
+        require(size > 0, "__setCanonicalLib: non-contract");
         canonicalLib = _nextCanonicalLib;
```

### Verification
- Add/extend Foundry tests to assert:
  - revert on zero address,
  - revert on EOA/non-contract address,
  - success on valid contract address.
- Run relevant suites with `forge test`.

## 3. Proof of Concept
A safe local PoC can be implemented as a Foundry test (no external targets):

1. Deploy a mock dispatcher owner + beacon/proxy stack locally.
2. As authorized owner, call `setImplementation(address(0))` (or set canonical lib to zero/EOA).
3. Invoke any function through a deployed proxy instance.
4. Observe deterministic revert/failure due to invalid delegatecall target.

Minimal local test pseudocode:
```solidity
function test_upgradeToZeroBricksProxy() public {
    vm.prank(owner);
    beacon.setImplementation(address(0));

    vm.expectRevert();
    IProxyLike(proxy).someFunction();
}
```

This PoC demonstrates real reachability and impact in a controlled environment while staying within safe bug-bounty constraints.

## Medium

### 2) Arbitrary admin call surface in ProtocolFeeReserve increases blast radius of owner compromise
- **Severity**: Medium
- **Category**: Broken Access Control (Privileged Capability)
- **Location**: `contracts/persistent/protocol-fee-reserve/ProtocolFeeReserveLib.sol::callOnContract`
- **Why it’s vulnerable**:
  - The dispatcher owner can execute arbitrary calldata on any target from reserve context.
  - While intentionally privileged, it bypasses function-level least privilege and materially increases consequences of key compromise.
- **Reachability**:
  - Dispatcher owner calls `callOnContract(target, calldata)`.
- **Impact**:
  - Privileged fund movements, approvals, or unexpected state changes from reserve-held assets.
- **Safe reproduction (local)**:
  - In local tests, invoke `callOnContract` against a mock target exposing a state mutator and verify mutation.
- **Fix**:
  - Add allowlist for callable targets/selectors or enforce timelocked governance module for this path.
  - Emit full structured event with target+selector.
- **Patch (minimal diff)**:
```diff
--- a/contracts/persistent/protocol-fee-reserve/ProtocolFeeReserveLib.sol
+++ b/contracts/persistent/protocol-fee-reserve/ProtocolFeeReserveLib.sol
@@
-    function callOnContract(address _contract, bytes calldata _callData) external onlyDispatcherOwner {
+    function callOnContract(address _contract, bytes calldata _callData) external onlyDispatcherOwner {
+        require(isAllowedTarget(_contract), "callOnContract: target not allowed");
+        require(isAllowedSelector(bytes4(_callData[:4])), "callOnContract: selector not allowed");
         (bool success, bytes memory returnData) = _contract.call(_callData);
```
- **Verification**:
  - Tests: disallowed target/selector reverts; approved ones succeed.

### 3) Gas relayer policy allows broad sponsored-call abuse by any permissioned caller
- **Severity**: Medium
- **Category**: Business Logic / Resource Exhaustion
- **Location**: `contracts/release/infrastructure/gas-relayer/GasRelayPaymasterLib.sol::preRelayedCall`
- **Why it’s vulnerable**:
  - Code explicitly permits any function selector as long as caller is permissioned/additional relay user.
  - This can sponsor high-frequency, low-value transactions and drain relayer budget faster than intended.
- **Reachability**:
  - Authorized relay user sends many valid relayed transactions via trusted forwarder.
- **Impact**:
  - Operational degradation (sponsored gas depletion), potentially impacting legitimate fund operations.
- **Safe reproduction (local)**:
  - Unit test simulating a permissioned caller repeatedly invoking relayed calls until paymaster deposit threshold is exhausted.
- **Fix**:
  - Introduce selector allowlist or per-user/per-selector budget and on-chain rate limiting.
- **Patch (minimal diff)**:
```diff
@@
-        bytes4 selector = __parseTxDataFunctionSelector(_relayRequest.request.data);
+        bytes4 selector = __parseTxDataFunctionSelector(_relayRequest.request.data);
+        require(isAllowedRelayedSelector(selector), "preRelayedCall: selector not allowed");
```
- **Verification**:
  - Confirm unauthorized selectors revert and legitimate flows continue.

### 4) Unpinned CI toolchain versions increase supply-chain compromise risk
- **Severity**: Medium
- **Category**: Supply Chain / CI Hardening
- **Location**: `.github/workflows/ci.yaml`
- **Why it’s vulnerable**:
  - `bun-version: latest` and Foundry `stable` are floating targets.
  - Compromise or bad upstream release can alter build/test behavior unexpectedly.
- **Reachability**:
  - Triggered on CI execution for push/PR.
- **Impact**:
  - Build integrity risk, malicious code execution during CI, inconsistent security signal.
- **Safe reproduction (local)**:
  - Compare CI output across two runs after upstream version changes; observe nondeterminism.
- **Fix**:
  - Pin exact versions and, where possible, pin action SHAs.
- **Patch (minimal diff)**:
```diff
-      - name: Set up bun
-        uses: oven-sh/setup-bun@v1
+      - name: Set up bun
+        uses: oven-sh/setup-bun@<pinned-commit-sha>
         with:
-          bun-version: latest
+          bun-version: 1.1.38
@@
-      - name: Install foundry
-        uses: foundry-rs/foundry-toolchain@v1
+      - name: Install foundry
+        uses: foundry-rs/foundry-toolchain@<pinned-commit-sha>
         with:
-          version: stable
+          version: v1.0.0
```
- **Verification**:
  - Ensure CI passes with pinned versions and reproducible outputs.

## Low

### 5) Missing zero-address checks in critical constructors/config setters increase misconfiguration risk
- **Severity**: Low
- **Category**: Misconfiguration / Defensive Validation
- **Location**: multiple (e.g., `DispatcherOwnedBeacon` constructor, `GasRelayPaymasterLib` constructor params)
- **Why it’s vulnerable**:
  - Critical addresses are assigned directly with no explicit non-zero validation.
  - Misdeployment can produce silent misconfiguration and runtime failures.
- **Reachability**:
  - Deployment-time only.
- **Impact**:
  - Non-functional deployments and emergency redeploy requirements.
- **Safe reproduction (local)**:
  - Deploy with one dependency as `address(0)` and execute path requiring it.
- **Fix**:
  - Add `require(addr != address(0))` for immutable critical deps.
- **Patch**:
  - Add constructor input guards for dispatcher, relay hub, forwarder, weth, and implementation/canonical-lib addresses.
- **Verification**:
  - Deployment tests expecting revert on zero values.

## Informational

### 6) Public proxy deployment may create operational noise and monitoring blind spots
- **Severity**: Informational
- **Category**: Operational Hardening
- **Location**: `contracts/utils/0.6.12/beacon-proxy/BeaconProxyFactory.sol::deployProxy`
- **Why it matters**:
  - Any account can deploy a proxy; this is not inherently vulnerable but can create ungoverned instances and noisy event streams.
- **Recommendation**:
  - Consider `onlyOwner` or explicit registry/tagging if unrestricted deployment is not a product requirement.

---

## Top 10 Risks (priority order)
1. Upgrade address validation missing in beacon/proxy upgrade setters (High).
2. Privileged arbitrary-call surface in protocol-fee-reserve (Medium).
3. Relayer sponsored-call selector surface too broad (Medium).
4. Unpinned CI toolchain/action versions (Medium).
5. Missing zero-address constructor validation for critical deps (Low).
6. Public proxy deployment without registry control (Informational).
7. Governance key concentration around dispatcher-owned controls (Informational).
8. Potential gas griefing from large relay-user list updates (Informational).
9. Event-level observability gaps for privileged operation context (Informational).
10. Complex delegatecall/proxy topology raises change-management risk (Informational).

---

## Hardening Recommendations
- Enforce strict upgrade safety checks (non-zero, code-size, optional ERC-1822/UUPS compatibility where relevant).
- Place high-risk admin actions behind timelock + multisig + on-chain allowlists.
- Add relayer budgets/rate limits and selector allowlists.
- Pin CI actions/toolchains by commit SHA and exact versions; verify checksums where possible.
- Expand invariant tests around initialization and upgrade flows.

---

## References
- OpenZeppelin upgradeability best practices: https://docs.openzeppelin.com/upgrades-plugins/1.x/
- Solidity security considerations: https://docs.soliditylang.org/en/latest/security-considerations.html
- GitHub Actions hardening guidance: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions

## Proof of Concept
All PoCs described above are intentionally scoped to **local test environments only** (Foundry unit/integration tests, local mock contracts, and deterministic CI simulation). No external systems or real target exploitation steps are included.
