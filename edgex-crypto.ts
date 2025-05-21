/**
 * @fileOverview Cryptographic utilities for EdgeX exchange API and L2 interactions.
 */
'use server';

import { keccak256, toUtf8Bytes } from 'ethers';
import * as starkwareCrypto from '@starkware-industries/starkware-crypto-utils';
import { addLog } from '@/lib/debug-logger';

const K_MODULUS_STRING = "0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";
const K_MODULUS = BigInt(K_MODULUS_STRING);

/**
 * Converts a JSON object or an array into a sorted query string.
 * This is a helper for `convertRequestBodyToString` and for query parameters.
 * @param data The JSON object or array.
 * @param sort Whether to sort keys (default: true).
 * @returns A string representation suitable for signature.
 */
function objectToSortedStringInternal(data: any, sort = true): string {
  if (data === null || data === undefined || typeof data === 'function') {
    return '';
  }

  if (typeof data !== 'object') {
    return String(data);
  }

  if (Array.isArray(data)) {
    return data.map(item => objectToSortedStringInternal(item, sort)).join('&');
  }

  const keys = sort ? Object.keys(data).sort() : Object.keys(data);
  return keys
    .map(key => {
      const value = objectToSortedStringInternal(data[key], sort);
      return `${key}=${value}`;
    })
    .join('&');
}

/**
 * Converts a request body (JSON object) into a sorted string format as per EdgeX docs for POST/PUT.
 * @param body The JSON request body.
 * @returns A string representation of the body, sorted alphabetically by keys.
 */
export async function convertRequestBodyToString(body: Record<string, any> | null | undefined): Promise<string> {
  if (!body || Object.keys(body).length === 0) {
    return '';
  }
  return objectToSortedStringInternal(body, true);
}

/**
 * Constructs the string to be signed for EdgeX Private API authentication.
 * @param timestamp The current timestamp (string or number).
 * @param method The HTTP method in uppercase (e.g., "GET", "POST").
 * @param requestPath The API request path (e.g., "/api/v1/resource").
 * @param paramsOrBodyString For GET requests, query parameters string (key=value&key2=value2, sorted alphabetically by key).
 *                           For POST/PUT, the stringified request body (already sorted).
 * @returns The concatenated string to be signed.
 */
export async function constructPrivateApiSignString(
  timestamp: string | number,
  method: string,
  requestPath: string,
  paramsOrBodyString?: string
): Promise<string> {
  const processedParamsOrBody = paramsOrBodyString || '';
  const result = String(timestamp) + method.toUpperCase() + requestPath + processedParamsOrBody;
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  await addLog('CryptoDebug', 'constructPrivateApiSignString inputs:', { timestamp, method, requestPath, processedParamsOrBody });
  await addLog('CryptoDebug', 'constructPrivateApiSignString result (messageToSign):', result);
  // End TODO
  return result;
}


/**
 * Generates the SHA3 (Keccak256) hash of the message string for Private API authentication.
 * @param message The string constructed by `constructPrivateApiSignString`.
 * @returns The Keccak256 hash as a hex string (e.g., "0x...").
 */
export async function hashPrivateApiMessage(message: string): Promise<string> {
  const messageBytes = toUtf8Bytes(message);
  const hash = keccak256(messageBytes);
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  await addLog('CryptoDebug', 'hashPrivateApiMessage input (messageToSign):', message);
  await addLog('CryptoDebug', 'hashPrivateApiMessage output (Keccak256 hash):', hash);
  // End TODO
  return hash;
}


/**
 * Generates authentication headers for EdgeX Private APIs.
 * @param l1PrivateKey The user's L1 private key (hex string, can be with or without "0x" prefix).
 * @param method The HTTP method (e.g., "GET", "POST").
 * @param path The API request path (base path, without query string, e.g., /api/v1/private/account/...).
 * @param paramsForSignature For GET: an object of query parameters that will actually be sent (keys sorted, values as strings).
 *                         For POST/PUT: the stringified request body (already sorted and stringified).
 * @returns An object containing `X-edgeX-Api-Timestamp` and `X-edgeX-Api-Signature`.
 */
export async function generatePrivateApiAuthHeaders(
  l1PrivateKey: string,
  method: string,
  path: string,
  paramsForSignature?: Record<string, string> | string
): Promise<{ 'X-edgeX-Api-Timestamp': string; 'X-edgeX-Api-Signature': string }> {

  if (typeof l1PrivateKey !== 'string') {
    const errorMsg = `L1 Private Key must be a string to call string methods. Received type: ${typeof l1PrivateKey}, value: ${l1PrivateKey}`;
    console.error('[CryptoError]', errorMsg, { receivedL1KeyType: typeof l1PrivateKey, keyPreview: String(l1PrivateKey).slice(0,10) }); 
    throw new TypeError(errorMsg);
  }
  if (l1PrivateKey.trim() === '') {
     const errorMsg = 'L1 Private Key cannot be an empty or whitespace-only string.';
     console.error('[CryptoError]', errorMsg);
     throw new Error(errorMsg);
  }
  
  const timestamp = Date.now().toString();
  
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  await addLog('CryptoDebug', 'generatePrivateApiAuthHeaders: Initial timestamp:', timestamp);
  await addLog('CryptoDebug', 'generatePrivateApiAuthHeaders: Method:', method);
  await addLog('CryptoDebug', 'generatePrivateApiAuthHeaders: Path:', path);
  await addLog('CryptoDebug', 'generatePrivateApiAuthHeaders: Received paramsForSignature (raw):', paramsForSignature);
  // End TODO

  let paramsOrBodyStringForSign = '';
  if (typeof paramsForSignature === 'object' && paramsForSignature !== null) {
    const queryParts: string[] = [];
    const sortedKeys = Object.keys(paramsForSignature).sort();
    for (const key of sortedKeys) {
        queryParts.push(`${key}=${paramsForSignature[key]}`);
    }
    paramsOrBodyStringForSign = queryParts.join('&');
    // TODO: Review and sanitize these logs before production or wider public sharing if still active.
    await addLog('CryptoDebug', 'generatePrivateApiAuthHeaders: Constructed paramsOrBodyStringForSign (GET):', paramsOrBodyStringForSign);
    // End TODO
  } else if (typeof paramsForSignature === 'string') {
    paramsOrBodyStringForSign = paramsForSignature;
    // TODO: Review and sanitize these logs before production or wider public sharing if still active.
    await addLog('CryptoDebug', 'generatePrivateApiAuthHeaders: Constructed paramsOrBodyStringForSign (POST/PUT):', paramsOrBodyStringForSign);
    // End TODO
  }

  const messageToSign = await constructPrivateApiSignString(timestamp, method, path, paramsOrBodyStringForSign);
  const hashedMessage = await hashPrivateApiMessage(messageToSign); 

  let msgHashBigInt = BigInt(hashedMessage);
  msgHashBigInt = msgHashBigInt % K_MODULUS;
  
  // Pass unpadded hex to starkwareCrypto.sign(), it handles internal fixMsgHashLen
  const msgHashForSigning = msgHashBigInt.toString(16); 

  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  await addLog('CryptoDebug', 'generatePrivateApiAuthHeaders: msgHashForSigning (after Keccak256 & modulo K_MODULUS):', msgHashForSigning.padStart(64, '0')); // Log padded for consistent length display
  // End TODO

  let privateKeyHexForStarkware = l1PrivateKey;
  if (privateKeyHexForStarkware.startsWith('0x')) {
    privateKeyHexForStarkware = privateKeyHexForStarkware.substring(2);
  }
  privateKeyHexForStarkware = privateKeyHexForStarkware.padStart(64, '0');
  
  // Commented out direct logging of private key parts for security when sharing code.
  // The technician must be informed of the key separately for comparison.
  // await addLog('CryptoDebug', 'L1 Private Key (for starkKeyPair - first 6, last 4 chars):', `${privateKeyHexForStarkware.substring(0,6)}...${privateKeyHexForStarkware.slice(-4)}`);
  // await addLog('CryptoDebug', 'L1 Private Key (cleaned length):', privateKeyHexForStarkware.length);


  const starkKeyPair = starkwareCrypto.ec.keyFromPrivate(privateKeyHexForStarkware, 'hex');
  const starkSignatureObject = starkwareCrypto.sign(starkKeyPair, msgHashForSigning);

  const rBN = starkSignatureObject.r;
  const sBN = starkSignatureObject.s;
  
  // Deriving Y from the key pair is more direct and less prone to errors than ec.g.mul
  const publicKeyYBN = starkKeyPair.getPublic().getY();

  const rHex = rBN.toString(16).padStart(64, '0');
  const sHex = sBN.toString(16).padStart(64, '0');
  const yHex = publicKeyYBN.toString(16).padStart(64, '0');
  
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  await addLog('CryptoDebug', 'Signature rHex:', rHex);
  await addLog('CryptoDebug', 'Signature sHex:', sHex);
  await addLog('CryptoDebug', 'Signature yHex (Public Key Y-coordinate):', yHex);
  // End TODO

  const starkSignature = rHex + sHex + yHex;
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  await addLog('CryptoDebug', 'Final Signature (X-edgeX-Api-Signature):', starkSignature);
  // End TODO


  if (!starkSignature || starkSignature.length !== 192) {
     throw new Error("L1 Signature generation failed or has incorrect length (expected 192 chars).");
  }

  return {
    'X-edgeX-Api-Timestamp': timestamp,
    'X-edgeX-Api-Signature': starkSignature,
  };
}


// --- L2 Signature Logic ---

/**
 * Get a StarkEx key pair from a private key.
 * @param l2PrivateKeyHex The L2 private key in hex format (can be with or without "0x" prefix).
 * @returns The StarkEx key pair.
 */
function getStarkKeyPair(l2PrivateKeyHex: string) {
  if (typeof l2PrivateKeyHex !== 'string') { 
    console.error('[CryptoError] L2 Private Key is not a string for getStarkKeyPair.', { keyType: typeof l2PrivateKeyHex });
    throw new TypeError('L2 Private Key must be a string for getStarkKeyPair.');
  }
  let cleanPrivateKey = l2PrivateKeyHex;
  if (cleanPrivateKey.startsWith('0x')) {
    cleanPrivateKey = cleanPrivateKey.substring(2);
  }
  return starkwareCrypto.ec.keyFromPrivate(cleanPrivateKey.padStart(64, '0'), 'hex');
}

/**
 * Signs a limit order message for StarkEx L2.
 * @param l2PrivateKeyHex The L2 private key.
 * @param order Parameters for the limit order hash function.
 * @returns The r and s components of the signature, each as a 64-character hex string.
 */
export async function signL2LimitOrder(
  l2PrivateKeyHex: string,
  order: {
    vaultIdSell: number | string;
    vaultIdBuy: number | string;
    amountSell: string;
    amountBuy: string;
    tokenSell: string;
    tokenBuy: string;
    nonce: number | string;
    expirationTimestamp: number | string;
    feeTokenId?: string;
    feeSourceVaultId?: number | string;
    feeLimit?: string;
  }
): Promise<{ r: string; s: string }> {
  const keyPair = getStarkKeyPair(l2PrivateKeyHex);
  let msgHash: string;

  if (order.feeTokenId && order.feeSourceVaultId !== undefined && order.feeLimit) {
    msgHash = starkwareCrypto.getLimitOrderMsgHashWithFee(
      order.vaultIdSell,
      order.vaultIdBuy,
      order.amountSell,
      order.amountBuy,
      order.tokenSell,
      order.tokenBuy,
      order.nonce,
      order.expirationTimestamp,
      order.feeTokenId,
      order.feeSourceVaultId,
      order.feeLimit
    );
  } else {
    msgHash = starkwareCrypto.getLimitOrderMsgHash(
      order.vaultIdSell,
      order.vaultIdBuy,
      order.amountSell,
      order.amountBuy,
      order.tokenSell,
      order.tokenBuy,
      order.nonce,
      order.expirationTimestamp
    );
  }
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  // await addLog('L2SignDebug', 'Limit Order Msg Hash:', msgHash);
  // End TODO
  const signature = starkwareCrypto.sign(keyPair, msgHash);
  const sigReturn = {
    r: signature.r.toString(16).padStart(64, '0'),
    s: signature.s.toString(16).padStart(64, '0')
  };
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  // await addLog('L2SignDebug', 'Limit Order Signature:', sigReturn);
  // End TODO
  return sigReturn;
}

/**
 * Signs a transfer message for StarkEx L2.
 * @param l2PrivateKeyHex The L2 private key.
 * @param transfer Parameters for the transfer hash function.
 * @returns The r and s components of the signature, each as a 64-character hex string.
 */
export async function signL2Transfer(
  l2PrivateKeyHex: string,
  transfer: {
    amount: string;
    nonce: number | string;
    senderVaultId: number | string;
    token: string;
    targetVaultId: number | string;
    targetPublicKey: string;
    expirationTimestamp: number | string;
    condition?: string;
    feeTokenId?: string;
    feeSourceVaultId?: number | string;
    feeLimit?: string;
  }
): Promise<{ r: string; s: string }> {
  const keyPair = getStarkKeyPair(l2PrivateKeyHex);
  let msgHash: string;

  if (transfer.feeTokenId && transfer.feeSourceVaultId !== undefined && transfer.feeLimit) {
     msgHash = starkwareCrypto.getTransferMsgHashWithFee(
        transfer.amount,
        transfer.nonce,
        transfer.senderVaultId,
        transfer.token,
        transfer.targetVaultId,
        transfer.targetPublicKey,
        transfer.expirationTimestamp,
        transfer.feeTokenId,
        transfer.feeSourceVaultId,
        transfer.feeLimit,
        transfer.condition
      );
  } else {
    msgHash = starkwareCrypto.getTransferMsgHash(
      transfer.amount,
      transfer.nonce,
      transfer.senderVaultId,
      transfer.token,
      transfer.targetVaultId,
      transfer.targetPublicKey,
      transfer.expirationTimestamp,
      transfer.condition
    );
  }
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  // await addLog('L2SignDebug', 'Transfer Msg Hash:', msgHash);
  // End TODO
  const signature = starkwareCrypto.sign(keyPair, msgHash);
  const sigReturn = {
    r: signature.r.toString(16).padStart(64, '0'),
    s: signature.s.toString(16).padStart(64, '0')
  };
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  // await addLog('L2SignDebug', 'Transfer Signature:', sigReturn);
  // End TODO
  return sigReturn;
}


/**
 * Constructs the withdrawal message string for L2 withdrawal, then signs it.
 * Based on EdgeX documentation snippet for "Withdrawal Signature Calculation".
 * @param l2PrivateKeyHex The L2 private key.
 * @param withdrawal Details for the withdrawal.
 * @returns The r and s components of the signature, each as a 64-character hex string.
 */
export async function signL2Withdrawal(
  l2PrivateKeyHex: string,
  withdrawal: {
    assetIdCollateral: string; // Asset ID for the collateral token (hex, e.g. from meta_data.coinList.starkExAssetId)
    positionId: string | number;       // User's account ID in Layer 2 (starkEx position_id)
    ethAddress: string;          // Destination Ethereum address for withdrawal (hex)
    nonce: string | number;            // Unique transaction identifier to prevent replay attacks
    expirationTimestamp: string | number; // Unix timestamp when signature expires (seconds)
    amount: string | number;           // Amount to withdraw in base units
  }
): Promise<{ r: string; s: string }> {
  const keyPair = getStarkKeyPair(l2PrivateKeyHex);

  const STARKEX_WITHDRAWAL_TO_ADDRESS_CONSTANT = BigInt(2); 

  const w1_hex = withdrawal.assetIdCollateral.startsWith('0x')
    ? withdrawal.assetIdCollateral
    : '0x' + withdrawal.assetIdCollateral;

  const ethAddress_hex = withdrawal.ethAddress.startsWith('0x')
    ? withdrawal.ethAddress
    : '0x' + withdrawal.ethAddress;

  let w5 = STARKEX_WITHDRAWAL_TO_ADDRESS_CONSTANT;
  w5 = (w5 << BigInt(64)) + BigInt(String(withdrawal.positionId));
  w5 = (w5 << BigInt(32)) + BigInt(String(withdrawal.nonce));
  w5 = (w5 << BigInt(64)) + BigInt(String(withdrawal.amount));
  w5 = (w5 << BigInt(32)) + BigInt(String(withdrawal.expirationTimestamp));
  w5 = w5 << BigInt(49); 
  
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  /*
  await addLog('L2SignDebug', 'Withdrawal Inputs for w5 calculation:', { 
    withdrawalToAddressConstant: STARKEX_WITHDRAWAL_TO_ADDRESS_CONSTANT.toString(),
    positionId: String(withdrawal.positionId),
    nonce: String(withdrawal.nonce),
    amount: String(withdrawal.amount),
    expirationTimestamp: String(withdrawal.expirationTimestamp),
    final_w5_before_hex_conversion: w5.toString() 
  });
  */
  // End TODO

  const w5_hex = '0x' + w5.toString(16);
  
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  // await addLog('L2SignDebug', 'Withdrawal Inputs (w1_hex, ethAddress_hex, w5_hex):', { w1_hex, ethAddress_hex, w5_hex });
  // End TODO

  const hashPart1 = starkwareCrypto.pedersen(w1_hex, ethAddress_hex);
  const msgHash = starkwareCrypto.pedersen(hashPart1, w5_hex);
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  // await addLog('L2SignDebug', 'Withdrawal Msg Hash (Pedersen):', msgHash);
  // End TODO

  const signature = starkwareCrypto.sign(keyPair, msgHash);
  const sigReturn = {
    r: signature.r.toString(16).padStart(64, '0'),
    s: signature.s.toString(16).padStart(64, '0')
  };
  // TODO: Review and sanitize these logs before production or wider public sharing if still active.
  // await addLog('L2SignDebug', 'Withdrawal Signature:', sigReturn);
  // End TODO
  return sigReturn;
}
