import { sha256 } from 'js-sha256';
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  getAssociatedTokenAddressSync,
} from '@solana/spl-token';
import {
  AccountMeta,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from '@solana/web3.js';

export type VaultAccount = {
  authority: PublicKey;
  curator: PublicKey;
  allocator: PublicKey;
  assetMint: PublicKey;
  sharesMint: PublicKey;
  assetVault: PublicKey;
  totalAssets: bigint;
  decimalsOffset: number;
  bump: number;
  paused: boolean;
  vaultId: bigint;
  liquidityAdapterId: bigint | null;
  maxAdapters: number;
  numAdapters: number;
  lastSyncSlot: bigint;
  validationEngine: PublicKey;
  trustlineEnabled: boolean;
};

export type AdapterConfigAccount = {
  vault: PublicKey;
  adapterId: bigint;
  adapterProgram: PublicKey;
  enabled: boolean;
  maxAllocationAbs: bigint;
  holdingAccount: PublicKey;
  name: string;
  bump: number;
};

export type AdapterPositionAccount = {
  vault: PublicKey;
  adapterId: bigint;
  principalDeployed: bigint;
  lastReportedAssets: bigint;
  lastReportedSlot: bigint;
  bump: number;
};

export type AdapterSnapshot = {
  id: bigint;
  configAddress: PublicKey;
  positionAddress: PublicKey;
  holdingAddress: PublicKey;
  config: AdapterConfigAccount | null;
  position: AdapterPositionAccount | null;
  holdingBalance: bigint | null;
};

type LiquidityAccounts = {
  config: PublicKey;
  position: PublicKey;
  holding: PublicKey;
  program: PublicKey;
};

const textEncoder = new TextEncoder();
const U64_BYTES = 8;
const OPTION_U64_BYTES = 1 + U64_BYTES;
export const TRUSTLINE_VALIDATION_ENGINE_PROGRAM_ID = new PublicKey(
  'E81TszYGg3oEgaQ4QGrW1cN843rQXGmqPMZbyNM2SrJK'
);
export const TRUSTLINE_GLOBAL_CONFIG_SEED = 'global_config';
export const TRUSTLINE_PROTOCOL_CONFIG_SEED = 'protocol_config';

function accountDiscriminator(name: string): Uint8Array {
  return Uint8Array.from(sha256.digest(`account:${name}`)).slice(0, 8);
}

function instructionDiscriminator(name: string): Uint8Array {
  return Uint8Array.from(sha256.digest(`global:${name}`)).slice(0, 8);
}

function encodeU32(value: number): Uint8Array {
  const buffer = new ArrayBuffer(4);
  new DataView(buffer).setUint32(0, value, true);
  return new Uint8Array(buffer);
}

function encodeU64(value: bigint): Uint8Array {
  const buffer = new ArrayBuffer(U64_BYTES);
  new DataView(buffer).setBigUint64(0, value, true);
  return new Uint8Array(buffer);
}

function encodePubkey(value: PublicKey): Uint8Array {
  return value.toBytes();
}

function encodeBool(value: boolean): Uint8Array {
  return Uint8Array.of(value ? 1 : 0);
}

function readPubkey(data: Uint8Array, offset: number): PublicKey {
  return new PublicKey(data.slice(offset, offset + 32));
}

function readU64(data: Uint8Array, offset: number): bigint {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return view.getBigUint64(offset, true);
}

function readBool(data: Uint8Array, offset: number): boolean {
  return data[offset] === 1;
}

function readOptionU64(data: Uint8Array, offset: number): bigint | null {
  const tag = data[offset];
  if (tag === 0) {
    return null;
  }
  return readU64(data, offset + 1);
}

function readFixedString(data: Uint8Array, offset: number, length: number): string {
  const slice = data.slice(offset, offset + length);
  return new TextDecoder().decode(slice).replace(/\0+$/, '').trim();
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function encodeVecU64(values: bigint[]): Uint8Array {
  const encodedValues = values.map((value) => encodeU64(value));
  return concatBytes([encodeU32(values.length), ...encodedValues]);
}

function encodeBytesVec(data: Uint8Array): Uint8Array {
  return concatBytes([encodeU32(data.length), data]);
}

function makePlaceholderAccount(programId: PublicKey): AccountMeta {
  return { pubkey: programId, isSigner: false, isWritable: false };
}

function withDiscriminator(
  instructionName: string,
  payloadParts: Uint8Array[]
): Buffer {
  return Buffer.from(
    concatBytes([instructionDiscriminator(instructionName), ...payloadParts])
  );
}

function assertDiscriminator(data: Uint8Array, expected: Uint8Array): void {
  for (let index = 0; index < expected.length; index += 1) {
    if (data[index] !== expected[index]) {
      throw new Error('Unexpected account discriminator');
    }
  }
}

export function decodeVaultAccount(data: Buffer | Uint8Array): VaultAccount {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  assertDiscriminator(bytes, accountDiscriminator('Vault'));

  let offset = 8;
  const authority = readPubkey(bytes, offset);
  offset += 32;
  const curator = readPubkey(bytes, offset);
  offset += 32;
  const allocator = readPubkey(bytes, offset);
  offset += 32;
  const assetMint = readPubkey(bytes, offset);
  offset += 32;
  const sharesMint = readPubkey(bytes, offset);
  offset += 32;
  const assetVault = readPubkey(bytes, offset);
  offset += 32;
  const totalAssets = readU64(bytes, offset);
  offset += 8;
  const decimalsOffset = bytes[offset];
  offset += 1;
  const bump = bytes[offset];
  offset += 1;
  const paused = readBool(bytes, offset);
  offset += 1;
  const vaultId = readU64(bytes, offset);
  offset += 8;
  const liquidityAdapterId = readOptionU64(bytes, offset);
  offset += OPTION_U64_BYTES;
  const maxAdapters = bytes[offset];
  offset += 1;
  const numAdapters = bytes[offset];
  offset += 1;
  const lastSyncSlot = readU64(bytes, offset);
  offset += 8;
  const validationEngine = readPubkey(bytes, offset);
  offset += 32;
  const trustlineEnabled = readBool(bytes, offset);

  return {
    authority,
    curator,
    allocator,
    assetMint,
    sharesMint,
    assetVault,
    totalAssets,
    decimalsOffset,
    bump,
    paused,
    vaultId,
    liquidityAdapterId,
    maxAdapters,
    numAdapters,
    lastSyncSlot,
    validationEngine,
    trustlineEnabled,
  };
}

export function decodeAdapterConfigAccount(
  data: Buffer | Uint8Array
): AdapterConfigAccount {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  assertDiscriminator(bytes, accountDiscriminator('AdapterConfig'));

  let offset = 8;
  const vault = readPubkey(bytes, offset);
  offset += 32;
  const adapterId = readU64(bytes, offset);
  offset += 8;
  const adapterProgram = readPubkey(bytes, offset);
  offset += 32;
  const enabled = readBool(bytes, offset);
  offset += 1;
  const maxAllocationAbs = readU64(bytes, offset);
  offset += 8;
  const holdingAccount = readPubkey(bytes, offset);
  offset += 32;
  const name = readFixedString(bytes, offset, 32);
  offset += 32;
  const bump = bytes[offset];

  return {
    vault,
    adapterId,
    adapterProgram,
    enabled,
    maxAllocationAbs,
    holdingAccount,
    name,
    bump,
  };
}

export function decodeAdapterPositionAccount(
  data: Buffer | Uint8Array
): AdapterPositionAccount {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  assertDiscriminator(bytes, accountDiscriminator('AdapterPosition'));

  let offset = 8;
  const vault = readPubkey(bytes, offset);
  offset += 32;
  const adapterId = readU64(bytes, offset);
  offset += 8;
  const principalDeployed = readU64(bytes, offset);
  offset += 8;
  const lastReportedAssets = readU64(bytes, offset);
  offset += 8;
  const lastReportedSlot = readU64(bytes, offset);
  offset += 8;
  const bump = bytes[offset];

  return {
    vault,
    adapterId,
    principalDeployed,
    lastReportedAssets,
    lastReportedSlot,
    bump,
  };
}

export function deriveAdapterConfigPda(
  vault: PublicKey,
  adapterId: bigint,
  programId: PublicKey
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [textEncoder.encode('adapter_config'), vault.toBytes(), encodeU64(adapterId)],
    programId
  )[0];
}

export function deriveAdapterPositionPda(
  vault: PublicKey,
  adapterId: bigint,
  programId: PublicKey
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [textEncoder.encode('adapter_position'), vault.toBytes(), encodeU64(adapterId)],
    programId
  )[0];
}

export function deriveUserShareAta(
  owner: PublicKey,
  sharesMint: PublicKey
): PublicKey {
  return getAssociatedTokenAddressSync(
    sharesMint,
    owner,
    false,
    TOKEN_2022_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID
  );
}

export function deriveUserAssetAta(
  owner: PublicKey,
  assetMint: PublicKey,
  assetTokenProgram: PublicKey
): PublicKey {
  return getAssociatedTokenAddressSync(
    assetMint,
    owner,
    false,
    assetTokenProgram,
    ASSOCIATED_TOKEN_PROGRAM_ID
  );
}

export function humanizeAddress(value?: PublicKey | null): string {
  if (!value) {
    return 'Unavailable';
  }
  const base58 = value.toBase58();
  return `${base58.slice(0, 4)}...${base58.slice(-4)}`;
}

export function formatUnits(
  amount: bigint | null | undefined,
  decimals: number,
  fractionDigits = 4
): string {
  if (amount === null || amount === undefined) {
    return '0';
  }

  const negative = amount < BigInt(0);
  const value = negative ? -amount : amount;
  const base = BigInt(10) ** BigInt(decimals);
  const whole = value / base;
  const fraction = value % base;
  const fractionString = fraction.toString().padStart(decimals, '0').slice(0, fractionDigits);
  const trimmedFraction = fractionString.replace(/0+$/, '');

  return `${negative ? '-' : ''}${whole.toString()}${
    trimmedFraction ? `.${trimmedFraction}` : ''
  }`;
}

export function parseAmountInput(value: string, decimals: number): bigint | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }

  if (!/^\d*\.?\d*$/.test(trimmed)) {
    throw new Error('Use digits only');
  }

  const [wholePart = '0', fractionPart = ''] = trimmed.split('.');
  if (fractionPart.length > decimals) {
    throw new Error(`Max ${decimals} decimals`);
  }

  const normalizedWhole = wholePart === '' ? '0' : wholePart;
  const normalizedFraction = `${fractionPart}${'0'.repeat(decimals)}`.slice(0, decimals);
  return (
    BigInt(normalizedWhole) * (BigInt(10) ** BigInt(decimals)) +
    BigInt(normalizedFraction || '0')
  );
}

export function parseU64Input(value: string): bigint | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  if (!/^\d+$/.test(trimmed)) {
    throw new Error('Use a whole number');
  }
  return BigInt(trimmed);
}

export function parseOptionalBytes(value: string): Uint8Array {
  const trimmed = value.trim();
  if (!trimmed) {
    return new Uint8Array();
  }

  if (trimmed.startsWith('0x')) {
    const raw = trimmed.slice(2);
    if (raw.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(raw)) {
      throw new Error('Hex data must use an even-length 0x-prefixed string');
    }
    const bytes = new Uint8Array(raw.length / 2);
    for (let index = 0; index < raw.length; index += 2) {
      bytes[index / 2] = Number.parseInt(raw.slice(index, index + 2), 16);
    }
    return bytes;
  }

  return textEncoder.encode(trimmed);
}

function mulDiv(
  value: bigint,
  numerator: bigint,
  denominator: bigint,
  rounding: 'floor' | 'ceiling'
): bigint {
  if (denominator === BigInt(0)) {
    throw new Error('Division by zero');
  }

  const product = value * numerator;
  const quotient = product / denominator;
  const remainder = product % denominator;

  if (rounding === 'ceiling' && remainder > BigInt(0)) {
    return quotient + BigInt(1);
  }

  return quotient;
}

export function convertToSharesPreview(
  assets: bigint,
  totalAssets: bigint,
  totalShares: bigint,
  decimalsOffset: number,
  rounding: 'floor' | 'ceiling'
): bigint {
  const offset = BigInt(10) ** BigInt(decimalsOffset);
  return mulDiv(assets, totalShares + offset, totalAssets + BigInt(1), rounding);
}

export function convertToAssetsPreview(
  shares: bigint,
  totalAssets: bigint,
  totalShares: bigint,
  decimalsOffset: number,
  rounding: 'floor' | 'ceiling'
): bigint {
  const offset = BigInt(10) ** BigInt(decimalsOffset);
  return mulDiv(shares, totalAssets + BigInt(1), totalShares + offset, rounding);
}

export function buildDepositInstruction(params: {
  programId: PublicKey;
  user: PublicKey;
  vault: PublicKey;
  assetMint: PublicKey;
  userAssetAccount: PublicKey;
  assetVault: PublicKey;
  sharesMint: PublicKey;
  userSharesAccount: PublicKey;
  assetTokenProgram: PublicKey;
  assets: bigint;
  minSharesOut: bigint;
  liquidityAccounts?: LiquidityAccounts;
}): TransactionInstruction {
  const optionalAccounts = params.liquidityAccounts
    ? [
        { pubkey: params.liquidityAccounts.config, isSigner: false, isWritable: false },
        { pubkey: params.liquidityAccounts.position, isSigner: false, isWritable: true },
        { pubkey: params.liquidityAccounts.holding, isSigner: false, isWritable: true },
        { pubkey: params.liquidityAccounts.program, isSigner: false, isWritable: false },
      ]
    : [
        makePlaceholderAccount(params.programId),
        makePlaceholderAccount(params.programId),
        makePlaceholderAccount(params.programId),
        makePlaceholderAccount(params.programId),
      ];

  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.user, isSigner: true, isWritable: true },
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.assetMint, isSigner: false, isWritable: false },
      { pubkey: params.userAssetAccount, isSigner: false, isWritable: true },
      { pubkey: params.assetVault, isSigner: false, isWritable: true },
      { pubkey: params.sharesMint, isSigner: false, isWritable: true },
      { pubkey: params.userSharesAccount, isSigner: false, isWritable: true },
      ...optionalAccounts,
      { pubkey: params.assetTokenProgram, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: withDiscriminator('deposit', [
      encodeU64(params.assets),
      encodeU64(params.minSharesOut),
    ]),
  });
}

export function buildMintInstruction(params: {
  programId: PublicKey;
  user: PublicKey;
  vault: PublicKey;
  assetMint: PublicKey;
  userAssetAccount: PublicKey;
  assetVault: PublicKey;
  sharesMint: PublicKey;
  userSharesAccount: PublicKey;
  assetTokenProgram: PublicKey;
  shares: bigint;
  maxAssetsIn: bigint;
  liquidityAccounts?: LiquidityAccounts;
}): TransactionInstruction {
  const optionalAccounts = params.liquidityAccounts
    ? [
        { pubkey: params.liquidityAccounts.config, isSigner: false, isWritable: false },
        { pubkey: params.liquidityAccounts.position, isSigner: false, isWritable: true },
        { pubkey: params.liquidityAccounts.holding, isSigner: false, isWritable: true },
        { pubkey: params.liquidityAccounts.program, isSigner: false, isWritable: false },
      ]
    : [
        makePlaceholderAccount(params.programId),
        makePlaceholderAccount(params.programId),
        makePlaceholderAccount(params.programId),
        makePlaceholderAccount(params.programId),
      ];

  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.user, isSigner: true, isWritable: true },
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.assetMint, isSigner: false, isWritable: false },
      { pubkey: params.userAssetAccount, isSigner: false, isWritable: true },
      { pubkey: params.assetVault, isSigner: false, isWritable: true },
      { pubkey: params.sharesMint, isSigner: false, isWritable: true },
      { pubkey: params.userSharesAccount, isSigner: false, isWritable: true },
      { pubkey: params.assetTokenProgram, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ...optionalAccounts,
    ],
    data: withDiscriminator('mint', [
      encodeU64(params.shares),
      encodeU64(params.maxAssetsIn),
    ]),
  });
}

export function buildWithdrawInstruction(params: {
  programId: PublicKey;
  user: PublicKey;
  vault: PublicKey;
  assetMint: PublicKey;
  userAssetAccount: PublicKey;
  assetVault: PublicKey;
  sharesMint: PublicKey;
  userSharesAccount: PublicKey;
  assetTokenProgram: PublicKey;
  assets: bigint;
  maxSharesIn: bigint;
}): TransactionInstruction {
  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.user, isSigner: true, isWritable: true },
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.assetMint, isSigner: false, isWritable: false },
      { pubkey: params.userAssetAccount, isSigner: false, isWritable: true },
      { pubkey: params.assetVault, isSigner: false, isWritable: true },
      { pubkey: params.sharesMint, isSigner: false, isWritable: true },
      { pubkey: params.userSharesAccount, isSigner: false, isWritable: true },
      { pubkey: params.assetTokenProgram, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: withDiscriminator('withdraw', [
      encodeU64(params.assets),
      encodeU64(params.maxSharesIn),
    ]),
  });
}

export function buildRedeemInstruction(params: {
  programId: PublicKey;
  user: PublicKey;
  vault: PublicKey;
  assetMint: PublicKey;
  userAssetAccount: PublicKey;
  assetVault: PublicKey;
  sharesMint: PublicKey;
  userSharesAccount: PublicKey;
  assetTokenProgram: PublicKey;
  shares: bigint;
  minAssetsOut: bigint;
}): TransactionInstruction {
  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.user, isSigner: true, isWritable: true },
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.assetMint, isSigner: false, isWritable: false },
      { pubkey: params.userAssetAccount, isSigner: false, isWritable: true },
      { pubkey: params.assetVault, isSigner: false, isWritable: true },
      { pubkey: params.sharesMint, isSigner: false, isWritable: true },
      { pubkey: params.userSharesAccount, isSigner: false, isWritable: true },
      { pubkey: params.assetTokenProgram, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: withDiscriminator('redeem', [
      encodeU64(params.shares),
      encodeU64(params.minAssetsOut),
    ]),
  });
}

export function buildPauseInstruction(programId: PublicKey, authority: PublicKey, vault: PublicKey) {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: vault, isSigner: false, isWritable: true },
    ],
    data: withDiscriminator('pause', []),
  });
}

export function buildUnpauseInstruction(
  programId: PublicKey,
  authority: PublicKey,
  vault: PublicKey
) {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: vault, isSigner: false, isWritable: true },
    ],
    data: withDiscriminator('unpause', []),
  });
}

export function buildTransferAuthorityInstruction(params: {
  programId: PublicKey;
  authority: PublicKey;
  vault: PublicKey;
  newAuthority: PublicKey;
}) {
  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.authority, isSigner: true, isWritable: true },
      { pubkey: params.vault, isSigner: false, isWritable: true },
    ],
    data: withDiscriminator('transfer_authority', [encodePubkey(params.newAuthority)]),
  });
}

export function buildSetTrustlineConfigInstruction(params: {
  programId: PublicKey;
  authority: PublicKey;
  vault: PublicKey;
  enabled: boolean;
}) {
  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.authority, isSigner: true, isWritable: true },
      { pubkey: params.vault, isSigner: false, isWritable: true },
    ],
    data: withDiscriminator('set_trustline_config', [
      encodePubkey(TRUSTLINE_VALIDATION_ENGINE_PROGRAM_ID),
      encodeBool(params.enabled),
    ]),
  });
}

export function buildSetRolesInstruction(params: {
  programId: PublicKey;
  authority: PublicKey;
  vault: PublicKey;
  curator: PublicKey;
  allocator: PublicKey;
}) {
  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.authority, isSigner: true, isWritable: true },
    ],
    data: withDiscriminator('set_roles', [
      encodePubkey(params.curator),
      encodePubkey(params.allocator),
    ]),
  });
}

export function buildAddAdapterInstruction(params: {
  programId: PublicKey;
  authority: PublicKey;
  vault: PublicKey;
  adapterId: bigint;
  adapterProgram: PublicKey;
  maxAllocationAbs: bigint;
  adapterHolding: PublicKey;
}) {
  const adapterConfig = deriveAdapterConfigPda(params.vault, params.adapterId, params.programId);
  const adapterPosition = deriveAdapterPositionPda(
    params.vault,
    params.adapterId,
    params.programId
  );

  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.authority, isSigner: true, isWritable: true },
      { pubkey: adapterConfig, isSigner: false, isWritable: true },
      { pubkey: adapterPosition, isSigner: false, isWritable: true },
      { pubkey: params.adapterHolding, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: withDiscriminator('add_adapter', [
      encodeU64(params.adapterId),
      encodePubkey(params.adapterProgram),
      encodeU64(params.maxAllocationAbs),
    ]),
  });
}

export function buildRemoveAdapterInstruction(params: {
  programId: PublicKey;
  authority: PublicKey;
  vault: PublicKey;
  adapterId: bigint;
}) {
  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.authority, isSigner: true, isWritable: true },
      {
        pubkey: deriveAdapterConfigPda(params.vault, params.adapterId, params.programId),
        isSigner: false,
        isWritable: true,
      },
      {
        pubkey: deriveAdapterPositionPda(params.vault, params.adapterId, params.programId),
        isSigner: false,
        isWritable: true,
      },
    ],
    data: withDiscriminator('remove_adapter', [encodeU64(params.adapterId)]),
  });
}

export function buildSetLiquidityAdapterInstruction(params: {
  programId: PublicKey;
  curator: PublicKey;
  vault: PublicKey;
  adapterId: bigint;
}) {
  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.curator, isSigner: true, isWritable: true },
    ],
    data: withDiscriminator('set_liquidity_adapter', [encodeU64(params.adapterId)]),
  });
}

export function buildSetAdapterCapsInstruction(params: {
  programId: PublicKey;
  curator: PublicKey;
  vault: PublicKey;
  adapterId: bigint;
  maxAllocationAbs: bigint;
}) {
  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.curator, isSigner: true, isWritable: true },
      {
        pubkey: deriveAdapterConfigPda(params.vault, params.adapterId, params.programId),
        isSigner: false,
        isWritable: true,
      },
    ],
    data: withDiscriminator('set_adapter_caps', [
      encodeU64(params.adapterId),
      encodeU64(params.maxAllocationAbs),
    ]),
  });
}

export function buildEnableAdapterInstruction(params: {
  programId: PublicKey;
  curator: PublicKey;
  vault: PublicKey;
  adapterId: bigint;
}) {
  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.curator, isSigner: true, isWritable: true },
      {
        pubkey: deriveAdapterConfigPda(params.vault, params.adapterId, params.programId),
        isSigner: false,
        isWritable: true,
      },
    ],
    data: withDiscriminator('enable_adapter', [encodeU64(params.adapterId)]),
  });
}

export function buildDisableAdapterInstruction(params: {
  programId: PublicKey;
  curator: PublicKey;
  vault: PublicKey;
  adapterId: bigint;
}) {
  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.curator, isSigner: true, isWritable: true },
      {
        pubkey: deriveAdapterConfigPda(params.vault, params.adapterId, params.programId),
        isSigner: false,
        isWritable: true,
      },
    ],
    data: withDiscriminator('disable_adapter', [encodeU64(params.adapterId)]),
  });
}

export function buildAllocateInstruction(params: {
  programId: PublicKey;
  allocator: PublicKey;
  vault: PublicKey;
  adapterId: bigint;
  adapterProgram: PublicKey;
  assetVault: PublicKey;
  adapterHolding: PublicKey;
  assetMint: PublicKey;
  assetTokenProgram: PublicKey;
  amount: bigint;
  data: Uint8Array;
}) {
  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.allocator, isSigner: true, isWritable: true },
      {
        pubkey: deriveAdapterConfigPda(params.vault, params.adapterId, params.programId),
        isSigner: false,
        isWritable: false,
      },
      {
        pubkey: deriveAdapterPositionPda(params.vault, params.adapterId, params.programId),
        isSigner: false,
        isWritable: true,
      },
      { pubkey: params.assetVault, isSigner: false, isWritable: true },
      { pubkey: params.adapterHolding, isSigner: false, isWritable: true },
      { pubkey: params.assetMint, isSigner: false, isWritable: false },
      { pubkey: params.adapterProgram, isSigner: false, isWritable: false },
      { pubkey: params.assetTokenProgram, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: withDiscriminator('allocate', [
      encodeU64(params.adapterId),
      encodeU64(params.amount),
      encodeBytesVec(params.data),
    ]),
  });
}

export function buildDeallocateInstruction(params: {
  programId: PublicKey;
  allocator: PublicKey;
  vault: PublicKey;
  adapterId: bigint;
  adapterProgram: PublicKey;
  assetVault: PublicKey;
  adapterHolding: PublicKey;
  assetMint: PublicKey;
  assetTokenProgram: PublicKey;
  amount: bigint;
  data: Uint8Array;
}) {
  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.allocator, isSigner: true, isWritable: true },
      {
        pubkey: deriveAdapterConfigPda(params.vault, params.adapterId, params.programId),
        isSigner: false,
        isWritable: false,
      },
      {
        pubkey: deriveAdapterPositionPda(params.vault, params.adapterId, params.programId),
        isSigner: false,
        isWritable: true,
      },
      { pubkey: params.assetVault, isSigner: false, isWritable: true },
      { pubkey: params.adapterHolding, isSigner: false, isWritable: true },
      { pubkey: params.assetMint, isSigner: false, isWritable: false },
      { pubkey: params.adapterProgram, isSigner: false, isWritable: false },
      { pubkey: params.assetTokenProgram, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: withDiscriminator('deallocate', [
      encodeU64(params.adapterId),
      encodeU64(params.amount),
      encodeBytesVec(params.data),
    ]),
  });
}

export function buildSyncTotalAssetsInstruction(params: {
  programId: PublicKey;
  curator: PublicKey;
  vault: PublicKey;
  assetVault: PublicKey;
  adapters: AdapterSnapshot[];
}) {
  const remainingAccounts = params.adapters.flatMap((adapter) => {
    if (!adapter.config) {
      throw new Error(`Adapter ${adapter.id.toString()} config could not be decoded.`);
    }
    return [
      {
        pubkey: adapter.configAddress,
        isSigner: false,
        isWritable: false,
      },
      {
        pubkey: adapter.positionAddress,
        isSigner: false,
        isWritable: true,
      },
      {
        pubkey: adapter.holdingAddress,
        isSigner: false,
        isWritable: false,
      },
      {
        pubkey: adapter.config.adapterProgram,
        isSigner: false,
        isWritable: false,
      },
    ];
  });

  return new TransactionInstruction({
    programId: params.programId,
    keys: [
      { pubkey: params.curator, isSigner: true, isWritable: true },
      { pubkey: params.vault, isSigner: false, isWritable: true },
      { pubkey: params.assetVault, isSigner: false, isWritable: false },
      ...remainingAccounts,
    ],
    data: withDiscriminator('sync_total_assets', [
      encodeVecU64(params.adapters.map((adapter) => adapter.id)),
    ]),
  });
}

export { TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID };
