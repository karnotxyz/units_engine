import { hash } from "starknet";

// Types based on the OpenRPC spec
export type Bytes32 = string; // hex string with 0x prefix
export type AccountAddress = Bytes32;
export type Nonce = number; // uint32

export interface Event {
  from_address: Bytes32;
  keys: Bytes32[];
  data: Bytes32[];
}

export type FinalityStatus = "ACCEPTED_ON_UNITS" | "ACCEPTED_ON_PROOF_STORE";

export type ExecutionStatus =
  | { type: "SUCCEEDED" }
  | { type: "REVERTED"; error: string };

export interface ReadValidity {
  type: "BLOCK" | "TIMESTAMP";
  block?: number;
  timestamp?: number;
}

export interface ReadVerifier {
  type: "ACCOUNT" | "IDENTITY";
  signer_address: Bytes32;
  identity_address?: Bytes32;
}

export type ReadType =
  | {
      type: "NONCE";
      nonce: Bytes32;
    }
  | {
      type: "TRANSACTION_RECEIPT";
      transaction_hash: Bytes32;
    }
  | {
      type: "CLASS";
      class_hash: Bytes32;
    }
  | {
      type: "CALL";
      contract_address: Bytes32;
      function_selector: Bytes32;
      calldata: Bytes32[];
    };

export interface ReadData {
  verifier: ReadVerifier;
  read_type: ReadType[];
  read_validity: ReadValidity;
  chain_id: Bytes32;
  version: "ONE";
}

export interface SignedReadData {
  read_data: ReadData;
  signature: Bytes32[];
}

export interface TransactionReceipt {
  transaction_hash: Bytes32;
  events: Event[];
  finality_status: FinalityStatus;
  execution_status: ExecutionStatus;
}

export type ClassVisibility = "PUBLIC" | "ACL";

export interface ResourceBounds {
  max_amount: number;
  max_price_per_unit: number;
}

export interface ResourceBoundsMapping {
  l1_gas: ResourceBounds;
  l1_data_gas: ResourceBounds;
  l2_gas: ResourceBounds;
}

class UnitsProvider {
  private rpcUrl: string;

  constructor(rpcUrl: string) {
    this.rpcUrl = rpcUrl;
  }

  private async makeRequest(method: string, params: any): Promise<any> {
    const response = await fetch(this.rpcUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: `units_${method}`,
        params,
      }),
    });

    const data = await response.json();
    if (data.error) {
      throw new Error(data.error.message);
    }
    return data.result;
  }

  // Write Methods

  async declareProgram(
    accountAddress: AccountAddress,
    signature: Bytes32[],
    nonce: Nonce,
    program: any,
    visibility: ClassVisibility,
    compiledProgramHash: Bytes32 | undefined,
    resourceBounds: ResourceBoundsMapping,
  ): Promise<{ transaction_hash: Bytes32 }> {
    return this.makeRequest("declareProgram", {
      declare_program: {
        account_address: accountAddress,
        signature: signature,
        nonce: nonce,
        program: program,
        compiled_program_hash: compiledProgramHash,
        class_visibility: visibility,
        resource_bounds: resourceBounds,
      },
    });
  }

  async sendTransaction(
    accountAddress: AccountAddress,
    signature: Bytes32[],
    nonce: Nonce,
    calldata: Bytes32[],
    resourceBounds: ResourceBoundsMapping,
  ): Promise<{ transaction_hash: Bytes32 }> {
    return this.makeRequest("sendTransaction", {
      send_transaction: {
        account_address: accountAddress,
        signature: signature,
        nonce: nonce,
        calldata: calldata,
        resource_bounds: resourceBounds,
      },
    });
  }

  async deployAccount(
    signature: Bytes32[],
    nonce: Nonce,
    constructorCalldata: Bytes32[],
    programHash: Bytes32,
    accountAddressSalt: Bytes32,
    resourceBounds: ResourceBoundsMapping,
  ): Promise<{ transaction_hash: Bytes32 }> {
    return this.makeRequest("deployAccount", {
      deploy_account: {
        signature: signature,
        nonce: nonce,
        constructor_calldata: constructorCalldata,
        program_hash: programHash,
        account_address_salt: accountAddressSalt,
        resource_bounds: resourceBounds,
      },
    });
  }

  // Read Methods

  async getProgram(programHash: Bytes32): Promise<{ program: any }> {
    return this.makeRequest("getProgram", {
      get_program: {
        class_hash: programHash,
      },
    });
  }

  async getNonce(
    accountAddress: AccountAddress,
    signedReadData?: SignedReadData,
  ): Promise<{ nonce: number }> {
    return this.makeRequest("getNonce", {
      get_nonce: {
        account_address: accountAddress,
        signed_read_data: signedReadData,
      },
    });
  }

  async getTransactionReceipt(
    transactionHash: Bytes32,
    signedReadData: SignedReadData,
  ): Promise<TransactionReceipt> {
    return this.makeRequest("getTransactionReceipt", {
      get_transaction_receipt: {
        transaction_hash: transactionHash,
        signed_read_data: signedReadData,
      },
    });
  }

  async getChainId(): Promise<{ chain_id: Bytes32 }> {
    return this.makeRequest("getChainId", {});
  }

  async call(
    contractAddress: Bytes32,
    entrypoint: Bytes32,
    calldata: Bytes32[],
    signedReadData: SignedReadData,
  ): Promise<{ result: Bytes32[] }> {
    return this.makeRequest("call", {
      call: {
        contract_address: contractAddress,
        function_name: entrypoint,
        calldata: calldata,
        signed_read_data: signedReadData,
      },
    });
  }
}

// Helper functions to hash ReadData

// Helper function to convert string to hex
function stringToHex(str: string): string {
  return "0x" + Buffer.from(str).toString("hex");
}

// Helper function to hash multiple values
function hashMany(values: string[]): string {
  return hash.computePoseidonHashOnElements(values);
}

// Hash function for ReadVerifier
function hashReadVerifier(verifier: ReadVerifier): string {
  if (verifier.type === "ACCOUNT") {
    return hashMany([stringToHex("account"), verifier.signer_address]);
  } else {
    // Ensure identity_address is defined when type is IDENTITY
    const identityAddr = verifier.identity_address || "0x0";
    return hashMany([
      stringToHex("identity"),
      verifier.signer_address,
      identityAddr,
    ]);
  }
}

// Hash function for ReadType
function hashReadType(readType: ReadType): string {
  switch (readType.type) {
    case "NONCE":
      return hashMany([stringToHex("nonce"), readType.nonce]);
    case "TRANSACTION_RECEIPT":
      return hashMany([
        stringToHex("transaction_receipt"),
        readType.transaction_hash,
      ]);
    case "CLASS":
      return hashMany([stringToHex("class"), readType.class_hash]);
    case "CALL":
      return hashMany([
        stringToHex("call"),
        readType.contract_address,
        readType.function_selector,
        hashMany(readType.calldata),
      ]);
  }
}

// Hash function for ReadValidity
function hashReadValidity(validity: ReadValidity): string {
  if (validity.type === "BLOCK") {
    const block = validity.block !== undefined ? validity.block : 0;
    return hashMany([stringToHex("block"), `0x${block.toString(16)}`]);
  } else {
    const timestamp = validity.timestamp !== undefined ? validity.timestamp : 0;
    return hashMany([stringToHex("timestamp"), `0x${timestamp.toString(16)}`]);
  }
}

// Hash function for ReadData
export function hashReadData(readData: ReadData): string {
  const readTypeHashes = readData.read_type.map(hashReadType);
  const readTypeHash = hashMany(readTypeHashes);

  return hashMany([
    stringToHex("read_string"),
    hashReadVerifier(readData.verifier),
    readTypeHash,
    hashReadValidity(readData.read_validity),
    readData.chain_id,
    hashMany([
      stringToHex("version"),
      "1", // Since version is always "ONE"
    ]),
  ]);
}

export { UnitsProvider };
