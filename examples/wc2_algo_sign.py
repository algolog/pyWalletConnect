from logging import basicConfig, DEBUG, INFO
from time import sleep
from dataclasses import dataclass
from pywalletconnect.client import WCClient
from algosdk.encoding import msgpack_encode, msgpack_decode, is_valid_address
from algosdk.transaction import SignedTransaction, calculate_group_id
from algosdk import account, mnemonic
from base64 import b64encode
import copy
from dotenv import dotenv_values

# Enable for debug output
basicConfig(level=INFO)


@dataclass(frozen=True)
class WCError:
    msg: str
    code: int


ALGORAND_MAINNET_CHAIN_ID = 'wGHE2Pwdvd7S12BL5FaOP20EGYesN73k'
ALGORAND_TESTNET_CHAIN_ID = 'SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe'

WC_ERROR_REJECTED = WCError('User Rejected Request', 4001)
WC_ERROR_UNAUTHORIZED = WCError('User Rejected Request', 4100)
WC_ERROR_UNSUPPORTED = WCError('Unsupported Operation', 4200)
WC_ERROR_INVALID_INPUT = WCError('Invalid Input', 4300)


def process_sign_txns(txns, key, opts=None):
    """
    Sign transactions with private key, see ARC-0001 for details.

    Args:
        txns (list): list of WalletTransactions
        key (str): private key
        opts (dict): optional parameters representing SignTxnsOpts

    Returns:
        tuple: result, error
            result (list): list of signed transactions
            error (WCError): one of WC_ERROR objects or None
    """
    signing_address = account.address_from_private_key(key)
    error = None
    result = []
    nogrp_utxns = []  # all unsigned input txns with their group stripped
    grp_ids = []      # all group_ids from input txns

    for seq_num, wallet_txn in enumerate(txns, 1):
        # extract the Transaction object for signing
        try:
            unsigned_txn = msgpack_decode(wallet_txn['txn'])
        except Exception:
            error = WC_ERROR_INVALID_INPUT
            break

        # save group-related info for group_id validation
        grp_ids.append(unsigned_txn.group)
        tmp_utxn = copy.deepcopy(unsigned_txn)
        tmp_utxn.group = None
        nogrp_utxns.append(tmp_utxn)

        # get other WalletTransaction properties
        auth_addr = wallet_txn.get('authAddr', None)
        signers = wallet_txn.get('signers', None)
        message = wallet_txn.get('message', '')
        stxn_is_present = 'stxn' in wallet_txn

        # reject multisigs
        if 'msig' in wallet_txn:
            error = WC_ERROR_UNSUPPORTED
            break

        # validate rekeyed requests
        if auth_addr:
            if not is_valid_address(auth_addr):
                error = WC_ERROR_INVALID_INPUT
                break
            if auth_addr != signing_address:
                error = WC_ERROR_UNAUTHORIZED
                break

        # human-readable group id as in algoexplorer
        group_id = unsigned_txn.group
        if group_id:
            group_id = b64encode(group_id).decode()

        # verbose txn report
        print('~'*70)
        print(f'Tx seq number: {seq_num}')
        print(f'Message (untrusted): {message}')
        print(f'authAddr: {auth_addr}')
        print(f'signers: {signers}')
        print(f'stxn_is_present: {stxn_is_present}')
        print(f'group_ID: {group_id}')
        print(f'tx_type: {unsigned_txn.type}')
        print(f'txn: {str(unsigned_txn)}')
        if getattr(unsigned_txn, 'rekey_to', None):
            print(f'WARNING: rekey_to present! - WARNING')
        if getattr(unsigned_txn, 'close_remainder_to', None):
            print(f'WARNING: close_remainder_to present! - WARNING')
        if getattr(unsigned_txn, 'close_assets_to', None):
            print(f'WARNING: close_assets_to present! - WARNING')
        print('~'*70)

        if signers == []:
            # when signers is an empty array we must not sign this txn
            out_txn = None
            if 'stxn' in wallet_txn:
                try:
                    stxn = msgpack_decode(wallet_txn['stxn'])
                    # check that unsigned part matches the input
                    if (
                        type(stxn) == SignedTransaction
                        and stxn.transaction == unsigned_txn
                    ):
                        out_txn = stxn
                    else:
                        raise ValueError('Bad stxn provided')
                except Exception:
                    error = WC_ERROR_INVALID_INPUT
                    break
        else:
            # TODO: extra validations when signers array is non-empty
            if unsigned_txn.sender != signing_address:
                if auth_addr is None:
                    print(f"WARNING: tx.sender {unsigned_txn.sender} "
                          f"is not from signing key {signing_address}")
            # just sign tx with the wallet key
            out_txn = unsigned_txn.sign(key)

        # encode the signed txn for output
        if out_txn is not None:
            out_txn = msgpack_encode(out_txn)
        result.append(out_txn)

    # group validation: only allow single tx or single group for now
    ref_grp_id = calculate_group_id(nogrp_utxns)
    if error is None:
        if not (
            len(grp_ids) == len(txns)
            and (all(gid == ref_grp_id for gid in grp_ids)
                 or (grp_ids == [None]))
        ):
            print(f"Group validation ERROR: {grp_ids}")
            error = WC_ERROR_UNSUPPORTED

    # must return array of the same length as the input
    if error is None:
        if len(result) != len(txns):
            error = WC_ERROR_INVALID_INPUT

    # clear the result in case there were any errors
    if error is not None:
        result = []

    return (result, error)


def WCCLIalgo():
    print("-= pyWalletConnect minimal demo - Algorand chain =-")

    # Load wallet account. Use .env for demo only,
    # better keep your keys in KMD or hw backed keyring
    env_vars = dotenv_values()
    wallet_chain_id = ALGORAND_MAINNET_CHAIN_ID
    wallet_key = mnemonic.to_private_key(env_vars["mnemonic"])
    wallet_address = account.address_from_private_key(wallet_key)
    wallet_project_id = env_vars['wc_project_id']
    signing_key = wallet_key    # can be another key for rekeyed accounts
    signing_address = account.address_from_private_key(signing_key)
    print(f"Chain ID: {wallet_chain_id}")
    print(f"Using account: {wallet_address}")
    print(f"Using signing account: {signing_address}")

    # set metadata
    WCClient.set_wallet_namespace('algorand')
    WCClient.set_project_id(wallet_project_id)  # Required for v2

    uri = input("Paste a Dapp WC URI: ")
    wclient = WCClient.from_wc_uri(uri)
    print("Connecting with the Dapp ...")
    req_id, req_chain_id, request_info = wclient.open_session()
    if req_chain_id != wallet_chain_id:
        # Chain id mismatch
        wclient.close()
        raise ValueError(f"Chain ID from Dapp ({req_chain_id}) is not the"
                         f" same as the wallet's ({wallet_chain_id}).")

    # Waiting for user accept the Dapp request
    user_ok = input(
        f"WalletConnect pairing request from {request_info['name']}. Approve? [y/N]: "
    )
    if user_ok.lower() != "y":
        print("User denied the pairing.")
        wclient.reject_session_request(req_id)
        return

    print("Accepted, continue connecting with the Dapp ...")
    wclient.reply_session_request(req_id, wallet_chain_id, wallet_address)

    print("Connected.")
    print(" To quit : Hit CTRL+C, or disconnect from Dapp.")
    print("Now waiting for dapp messages ...")
    while True:
        try:
            sleep(0.3)
            # get_message return : (id, method, params) or (None, "", [])
            wc_message = wclient.get_message()
            request_id = wc_message[0]
            method = wc_message[1]
            params = wc_message[2]
            if request_id is not None:
                print("\n <---- Received WalletConnect wallet query: ")
                print(wc_message)
                if method == "wc_sessionRequest" or method == "wc_sessionPayload":
                    # Read if v2 and convert to v1 format
                    if params.get("request"):
                        method = params["request"].get("method")
                        params = params["request"].get("params")

                # Detect quit
                #  v1 disconnect
                if (
                    method == "wc_sessionUpdate"
                    and not params[0]["approved"]
                ):
                    print("User disconnects from Dapp (WC v1).")
                    break
                #  v2 disconnect
                if method == "wc_sessionDelete" and params.get("message"):
                    print("User disconnects from Dapp (WC v2).")
                    print("Reason :", params["message"])
                    break
                # Process the signing request here
                if method == 'algo_signTxn':
                    sign_txn_opts = params[1] if len(params) > 1 else None
                    result, err = process_sign_txns(params[0],
                                                    signing_key,
                                                    sign_txn_opts)
                    if err is not None:
                        wclient.reply_error(request_id, err.msg, err.code)
                        print(f"----> Replied with error: {err.code} - {err.msg}")
                    else:
                        approve_ask = input('Approve (y/N)?: ').lower()
                        if approve_ask == 'y':
                            wclient.reply(request_id, result)
                            print(f"----> Replied with {len(result)} signed Txns.")
                        else:
                            err = WC_ERROR_REJECTED
                            wclient.reply_error(request_id, err.msg, err.code)
                            print(f"----> Replied with error: {err.code} - {err.msg}")

        except KeyboardInterrupt:
            print("Interrupted.")
            break
    wclient.close()
    print("WC disconnected.")


if __name__ == "__main__":
    WCCLIalgo()
