package com.hyperdht

/** Ed25519 keypair for HyperDHT identity. */
data class KeyPair(
    val publicKey: ByteArray,
    val secretKey: ByteArray,
) {
    companion object {
        /** Generate a random keypair. */
        fun generate(): KeyPair {
            val pk = ByteArray(32)
            val sk = ByteArray(64)
            Native.keypairGenerate(pk, sk)
            return KeyPair(pk, sk)
        }

        /** Derive a deterministic keypair from a 32-byte seed. */
        fun fromSeed(seed: ByteArray): KeyPair {
            require(seed.size == 32) { "Seed must be 32 bytes" }
            val pk = ByteArray(32)
            val sk = ByteArray(64)
            Native.keypairFromSeed(seed, pk, sk)
            return KeyPair(pk, sk)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KeyPair) return false
        return publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int = publicKey.contentHashCode()
}
