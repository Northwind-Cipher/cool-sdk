/**
 * CooL
 * Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Verifiable authorization for agents and services:
 * principals → delegation → request → decision → enforcement → confirmation.
 *
 *   import { createAuthorizationRequest, decide, ToolGateway } from "cool-nwc/authz";
 */
export { PrincipalDirectory, enrollPrincipal, principalEvent } from "./principal";
export type { IdentityBasis, PrincipalEvent, PrincipalEventKind, PrincipalKind, PrincipalRecord, PrincipalState, PrincipalStatus } from "./principal";
export { grantDelegation, scopeExcess, verifyDelegationChain } from "./delegation";
export type { ChainOptions, ChainRequest, Delegation, Scope } from "./delegation";
export { commitValue, contextMatches, createAuthorizationRequest, normalize, paramsMatch, requestDigest } from "./request";
export type { AuthorizationRequest, CommitmentScheme, RequestInput, RequestSecrets } from "./request";
export { EVALUATOR, decide, decisionFacts, verifyDecision } from "./decision";
export type { Assurance, AuthorizationDecision, AuthzDecisionValue, DecisionChecks, DecisionReport, VerifyDecisionOptions } from "./decision";
export { FileNonceStore, MemoryNonceStore } from "./replay";
export type { ConsumeResult, NonceStore } from "./replay";
export { compareExecution } from "./execution";
export type { ExecutionContext } from "./execution";
export { ToolGateway, verifyConfirmation } from "./gateway";
export type { ConfirmationOutcome, ExternalConfirmation, GatewayOptions, Invocation, InvocationResult, ToolDefinition } from "./gateway";
export { digestOf, signObject, verifyIntegrity, verifyTrusted } from "./signed";
export type { Signed } from "./signed";
