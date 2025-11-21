import {
  Account,
  Call,
  InvocationsSignerDetails,
  Provider,
  Signature,
  stark,
  hash,
  Signer,
  ec,
  selector,
  constants,
  Deployer,
} from "starknet";
import {
  ClassVisibility,
  hashReadData,
  ReadData,
  ReadType,
  SignedReadData,
  TransactionReceipt,
  UnitsProvider,
} from "./provider";

type DeployAccountParams = {
  programHash: string;
  salt: string;
  constructorArgs: string[];
};

class UnitsAccount {
  private unitsProvider: UnitsProvider;
  private address: string;
  private privateKey: string;
  private starknetAccount: Account;

  // Optional fields available when creating account with `newUndeployedAccount`
  private deployAccountParams: DeployAccountParams;

  static newUndeployedAccount(
    unitsProvider: UnitsProvider,
    programHash: string,
    salt: string,
    constructorArgs: string[],
    privateKey: string,
  ): UnitsAccount {
    const address = hash.calculateContractAddressFromHash(
      salt,
      programHash,
      constructorArgs,
      "0x0",
    );
    return new UnitsAccount(unitsProvider, address, privateKey, {
      programHash,
      salt,
      constructorArgs,
    });
  }

  constructor(
    unitsProvider: UnitsProvider,
    address: string,
    privateKey: string,
    deployAccountParams?: DeployAccountParams,
  ) {
    this.unitsProvider = unitsProvider;
    this.address = address;
    this.privateKey = privateKey;
    this.deployAccountParams = deployAccountParams;

    // Not assinging a URL as this is a dummy provider to build an account
    // We will not use it for making calls
    let provider = new Provider({
      nodeUrl: "",
    });
    this.starknetAccount = new Account({
      provider,
      address: this.address,
      signer: this.privateKey,
      cairoVersion: "1",
      transactionVersion: "0x3",
    });
  }

  getProvider(): UnitsProvider {
    return this.unitsProvider;
  }

  getAddress(): string {
    return this.address;
  }

  async buildInvokeSignerDetails(
    nonce?: number,
  ): Promise<InvocationsSignerDetails> {
    return {
      version: "0x3",
      nonce: nonce !== undefined ? nonce : await this.getNonce(),
      resourceBounds: {
        l1_gas: {
          max_amount: BigInt(10000),
          max_price_per_unit: BigInt(1),
        },
        l1_data_gas: {
          max_amount: BigInt(10000),
          max_price_per_unit: BigInt(1),
        },
        l2_gas: {
          max_amount: BigInt(10000000),
          max_price_per_unit: BigInt(2214382549775320),
        },
      },
      tip: "0",
      paymasterData: [],
      accountDeploymentData: [],
      nonceDataAvailabilityMode: "L1",
      feeDataAvailabilityMode: "L1",
      walletAddress: this.address,
      cairoVersion: "1",
      // @ts-ignore
      chainId: (await this.unitsProvider.getChainId()).chain_id,
    };
  }

  // TODO: Add read signature support
  async getNonce(): Promise<number> {
    const nonce = await this.unitsProvider.getNonce(this.address);
    return nonce.nonce;
  }

  async declareProgram(
    program: any,
    compiledProgramHash: string,
    visibility: ClassVisibility,
  ): Promise<{ transaction_hash: string }> {
    const signerDetails = await this.buildInvokeSignerDetails();
    const declarePayload = await this.starknetAccount.buildDeclarePayload(
      {
        contract: program,
        compiledClassHash: compiledProgramHash,
      },
      signerDetails,
    );

    const programId = await this.unitsProvider.declareProgram(
      this.address,
      buildSignature(declarePayload.signature),
      Number(signerDetails.nonce),
      {
        ...declarePayload.contract,
        sierra_program: stark.decompressProgram(
          // @ts-ignore
          declarePayload.contract.sierra_program,
        ),
      },
      visibility,
      compiledProgramHash,
    );
    return programId;
  }

  async deployProgram(
    programHash: string,
    constructorArgs: string[],
    salt: string,
  ): Promise<{ transaction_hash: string; program_address: string }> {
    const unique = true;

    const deployer = new Deployer();
    const udcDeployPayload = deployer.buildDeployerCall(
      {
        classHash: programHash,
        constructorCalldata: constructorArgs,
        salt,
        unique,
      },
      this.address,
    );
    const sendTransactionResponse = await this.sendTransaction(
      udcDeployPayload.calls,
    );

    const receipt = await this.waitForTransaction(
      sendTransactionResponse.transaction_hash,
    );

    return {
      transaction_hash: sendTransactionResponse.transaction_hash,
      program_address: receipt.events[0].data[0],
    };
  }

  async sendTransaction(
    calldata: Array<Call>,
  ): Promise<{ transaction_hash: string }> {
    const signerDetails = await this.buildInvokeSignerDetails();
    const invocation = await this.starknetAccount.buildInvocation(
      calldata,
      signerDetails,
    );
    let calldataString: string[] = [];
    if (Array.isArray(invocation.calldata)) {
      // @ts-ignore
      // TODO: Fix type error
      calldataString = invocation.calldata.map((x) => toHex(x));
    }

    const sendTransactionResponse = await this.unitsProvider.sendTransaction(
      this.address,
      buildSignature(invocation.signature),
      Number(signerDetails.nonce),
      calldataString,
    );
    return sendTransactionResponse;
  }

  async deploySelf() {
    const signerDetails = await this.buildInvokeSignerDetails(0);
    const deloyAccountPayload =
      await this.starknetAccount.buildAccountDeployPayload(
        {
          classHash: this.deployAccountParams.programHash,
          constructorCalldata: this.deployAccountParams.constructorArgs,
          addressSalt: this.deployAccountParams.salt,
        },
        signerDetails,
      );

    const deployAccountResponse = await this.unitsProvider.deployAccount(
      buildSignature(deloyAccountPayload.signature),
      Number(signerDetails.nonce),
      this.deployAccountParams.constructorArgs,
      this.deployAccountParams.programHash,
      this.deployAccountParams.salt,
    );

    return deployAccountResponse;
  }

  async getTransactionReceipt(
    transactionHash: string,
  ): Promise<TransactionReceipt> {
    const signedReadData = await this.buildSignedReadData([
      {
        type: "TRANSACTION_RECEIPT",
        transaction_hash: transactionHash,
      },
    ]);
    return this.unitsProvider.getTransactionReceipt(
      transactionHash,
      signedReadData,
    );
  }

  async call(
    contractAddress: string,
    entrypoint: string,
    calldata: string[],
  ): Promise<{ result: string[] }> {
    const entrypointSelector = selector.getSelectorFromName(entrypoint);
    const signedReadData = await this.buildSignedReadData([
      {
        type: "CALL",
        contract_address: contractAddress,
        function_selector: entrypointSelector,
        calldata: calldata,
      },
    ]);
    return this.unitsProvider.call(
      contractAddress,
      entrypoint,
      calldata,
      signedReadData,
    );
  }

  async waitForTransaction(
    transactionHash: string,
  ): Promise<TransactionReceipt> {
    const MAX_ATTEMPTS = 10;
    const SLEEP_TIME_MS = 200;

    let receipt = null;
    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      try {
        receipt = await this.getTransactionReceipt(transactionHash);
        if (receipt) {
          break;
        }
      } catch (error) {}
      await new Promise((resolve) => setTimeout(resolve, SLEEP_TIME_MS));
    }

    if (!receipt) {
      throw new Error(
        `Failed to get transaction receipt after ${MAX_ATTEMPTS} attempts`,
      );
    }

    return receipt;
  }

  async buildSignedReadData(readTypes: ReadType[]): Promise<SignedReadData> {
    let read_data: ReadData = {
      verifier: {
        type: "ACCOUNT",
        signer_address: this.address,
      },
      read_type: readTypes,
      read_validity: {
        type: "TIMESTAMP",
        timestamp: Math.floor(Date.now() / 1000) + 10,
      },
      // @ts-ignore
      chain_id: (await this.unitsProvider.getChainId()).chain_id,
      version: "ONE",
    };

    const signature = ec.starkCurve.sign(
      hashReadData(read_data),
      this.privateKey,
    );

    return {
      read_data,
      signature: [toHex(signature.r), toHex(signature.s)],
    };
  }
}

function toHex(value: bigint | string): string {
  if (typeof value === "string" && value.startsWith("0x")) {
    return value;
  }
  const hex = BigInt(value).toString(16);
  return hex.startsWith("0x") ? hex : `0x${hex}`;
}

function buildSignature(signature?: Signature) {
  if (!signature) {
    throw new Error("Signature is not available");
  }
  return Array.isArray(signature)
    ? signature.map((sig) => toHex(sig))
    : [toHex(signature.r), toHex(signature.s)];
}

export { UnitsAccount };
