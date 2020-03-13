from pybtc import *

a1 = Address("3fe09ec4cf427f7d5a105377f3531187d434c544d4689d2270b9b490b68ddafb", testnet=1)
a2 = Address("a3a2858c6c35fef8f07c4a39d669e174046f22d81e0caa0510fcdf64f8218041", testnet=1)
a = ScriptAddress.multisig(2,2,[a1.public_key, a2.public_key])


b1 = Address("b07b27e82614fdad7369f68f2c12ef4f9843e642d67cfe0834a80858e6696ed9", testnet=1)
b2 = Address("2baf551df7a3891d19b2d2b344dc21a30390a12b06770cf1d658957b4297713e", testnet=1)
b3 = Address("3da79d0afb511bd837d6ba683e4597998f9d5d07de73678298b7baf5681ae06b", testnet=1)

b = ScriptAddress.multisig(2, 3, [b1.public_key, b2.public_key, b3.public_key])


w = ScriptAddress(a.script_hex + OP_0.hex() + b.script_hex, testnet=True)

print(w.address)

tx = Transaction(testnet=True)

tx.add_input("e8dac71b52a66db9ac9affa80db397bc616f0acb72464ed0f9658480398e7c54",
             0, address=w.address,
             amount= 1000000,
             redeem_script=w.script_hex)

tx.add_output(980000, "tb1qu4ad4sa0mtf5z30w57ap98l8dnqsdne0zkelyf")

script_code = int_to_var_int(len(w.script_hex)) + bytes_from_hex(w.script_hex)
private_keys = [a1.private_key.hex, a2.private_key.hex, b1.private_key.hex, b3.private_key.hex]
sighash = tx.sig_hash_segwit(0, 1000000, script_pub_key=script_code)
sig = [sign_message(sighash, p, 0) + bytes([SIGHASH_ALL]) for p in private_keys]
tx["vIn"][0]['txInWitness'] = [s.hex() for s in sig]
tx["vIn"][0]['txInWitness'].append(w.script_hex)
tx["vIn"][0]["scriptSig"]  = ""
tx["segwit"]  = 1
print(tx)
tx.commit()
print(tx.serialize())



