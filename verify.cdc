// This does two things:
// 1. Checks that `sig` came from `msg`
// 2. Checks that `sig` was signed by `address` using `keyIndex`

pub fun main(address: Address, keyIndex: Int, sig: String, msg: String): Bool {
  let account = getAccount(address)
  let accountKey = account.keys.get(keyIndex: keyIndex) ?? panic("This keyIndex does not exist in this account")
  let key = accountKey.publicKey
  let sig = sig.decodeHex()
  let msg = msg.decodeHex()
  return key.verify(
    signature: sig, 
    signedData: msg, 
    domainSeparationTag: "FLOW-V0.0-user", 
    hashAlgorithm: HashAlgorithm.SHA3_256
  )
}