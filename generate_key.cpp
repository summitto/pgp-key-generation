/*TODO
- no namespace CryptoPP
- template Identity hash seperate
- consts for key_flags_subpacket and replace hardcoded hex flags in key gen

*/
	

#include "generate_key.h"
#include "derived_key.h"
#include "errors.h"
#include <sodium.h>
#include <ctime>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>


using namespace CryptoPP;

template <unsigned int HASH_SIZE = 32>
class IdentityHash : public HashTransformation
{
public:
    constexpr const static auto DIGESTSIZE = HASH_SIZE;

    static const char * StaticAlgorithmName()
    {
        return "IdentityHash";
    }

    IdentityHash() : m_digest(HASH_SIZE), m_idx(0) {}

    virtual unsigned int DigestSize() const
    {
        return DIGESTSIZE;
    }

    virtual void Update(const byte *input, size_t length)
    {
        size_t s = STDMIN(STDMIN<size_t>(DIGESTSIZE, length),
                                         DIGESTSIZE - m_idx);    
        if (s)
            ::memcpy(&m_digest[m_idx], input, s);
        m_idx += s;
    }

    virtual void TruncatedFinal(byte *digest, size_t digestSize)
    {
        ThrowIfInvalidTruncatedSize(digestSize);

        if (m_idx != DIGESTSIZE)
            throw Exception(Exception::OTHER_ERROR, "Input size must be " + IntToString(DIGESTSIZE));

        if (digest)
            ::memcpy(digest, m_digest, digestSize);

        m_idx = 0;
    }

private:
    SecByteBlock m_digest;
    size_t m_idx;
};

/**
 *  Generate a complete key, including the required signatures
 *
 *  @param  master      The master key to derive everything from
 *  @param  user        The user to create a key for
 *  @param  creation    The creation timestamp for the key
 *  @param  signature   The creation timestamp for the signature
 *  @param  expiration  The expiration timestamp for the signature
 *  @param  context     The context to use for deriving the keys
 */
std::vector<pgp::packet> generate_key(const master_key &master, std::string user, uint32_t creation, uint32_t signature, uint32_t expiration, boost::string_view context)
{
    // the size of our secret keys
    //constexpr const auto secret_key_size = crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES;
	
	// There is no easily found size const for defining key length in cryptopp
	constexpr const size_t SECRETKEYBYTES = 32;
	constexpr const size_t PUBLICKEYBYTES = 64;

    // pgp likes the expiration timestamp to not be a timestamp (but still call it that)
    // but instead define it as the number of seconds since the key creation timestamp
    expiration -= creation;

    // create an error checker
    error_checker<0> checker;

    // derive the keys from the master
    derived_key<SECRETKEYBYTES>    main_key_derivation             { master, 1, context };
    derived_key<SECRETKEYBYTES>    signing_key_derivation          { master, 2, context };
    derived_key<SECRETKEYBYTES>    encryption_key_derivation       { master, 3, context };
    derived_key<SECRETKEYBYTES>    authentication_key_derivation   { master, 4, context };

    // holders for the key data - public keys get an extra byte because of the leading 0x40 byte that we need to add for pgp to work
    std::vector<uint8_t>            main_key_public             (PUBLICKEYBYTES + 1);           // main key, for signing and certification
    std::vector<uint8_t>            main_key_secret             (SECRETKEYBYTES);               // using ecdsa curve
    std::vector<uint8_t>            signing_key_public          (PUBLICKEYBYTES + 1);           // signing and certification subkey
    std::vector<uint8_t>            signing_key_secret          (SECRETKEYBYTES);               // using ecdsa curve
    std::vector<uint8_t>            encryption_key_public       (PUBLICKEYBYTES + 1);   // the subkey used for encryption
    std::vector<uint8_t>            encryption_key_secret       (SECRETKEYBYTES);       // using curve25519
    std::vector<uint8_t>            authentication_key_public   (PUBLICKEYBYTES + 1);           // the subkey used for authentication
    std::vector<uint8_t>            authentication_key_secret   (SECRETKEYBYTES);               // using ecdsa curve again


	AutoSeededRandomPool prng;

	ECDSA<ECP, IdentityHash<32>>::PrivateKey k1;
	k1.Initialize( prng, ASN1::secp256r1() );

	const Integer& x1 = k1.GetPrivateExponent();
	std::cout << "K1: " << std::hex << x1 << std::dec << std::endl;

	ECDSA<ECP, IdentityHash<32>>::PrivateKey mainKeySecret;
	CryptoPP::Integer mainKeySecret_x;
	mainKeySecret_x.Decode(main_key_derivation.data(), SECRETKEYBYTES);

	mainKeySecret.Initialize(ASN1::secp256r1(), mainKeySecret_x);
		
	const Integer& mainKeySecret_exponent = mainKeySecret.GetPrivateExponent();
	mainKeySecret_exponent.Encode(main_key_secret.data(), main_key_secret.size());
	
	std::cout << "mainKeySecret_exponent: " <<  mainKeySecret_exponent << std::endl;
	
	ECDSA<ECP, IdentityHash<32>>::PublicKey mainKeyPublic;
	mainKeySecret.MakePublicKey(mainKeyPublic);
	
	const ECP::Point& mainKeyPublic_q = mainKeyPublic.GetPublicElement();
	mainKeyPublic_q.x.Encode(main_key_public.data() + 1, 32);
	mainKeyPublic_q.y.Encode(main_key_public.data() + 1 + mainKeyPublic_q.x.MinEncodedSize(), 32);

	std::cout << "Public Key at generation - X:" <<std::hex << mainKeyPublic_q.x << " - Y: " <<  mainKeyPublic_q.y << std::dec << std::endl;



	ECDSA<ECP, IdentityHash<32>>::PrivateKey signingKeySecret;
	CryptoPP::Integer signingKeySecret_x;
	signingKeySecret_x.Decode(signing_key_derivation.data(), SECRETKEYBYTES);

	signingKeySecret.Initialize(ASN1::secp256r1(), signingKeySecret_x);
	
	const Integer& signingKeySecret_exponent = signingKeySecret.GetPrivateExponent();
	signingKeySecret_exponent.Encode(signing_key_secret.data(), signing_key_secret.size());
	
	ECDSA<ECP, IdentityHash<32>>::PublicKey signingKeyPublic;
	signingKeySecret.MakePublicKey(signingKeyPublic);
	
	const ECP::Point& signingKeyPublic_q = signingKeyPublic.GetPublicElement();
	signingKeyPublic_q.x.Encode(signing_key_public.data() + 1, 32);
	signingKeyPublic_q.y.Encode(signing_key_public.data() + 1 + signingKeyPublic_q.x.MinEncodedSize(), 32);



	ECDSA<ECP, IdentityHash<32>>::PrivateKey encryptionKeySecret;
	CryptoPP::Integer encryptionKeySecret_x;
	encryptionKeySecret_x.Decode(encryption_key_derivation.data(), SECRETKEYBYTES);

	encryptionKeySecret.Initialize(ASN1::secp256r1(), encryptionKeySecret_x);
	
	const Integer& encryptionKeySecret_exponent = encryptionKeySecret.GetPrivateExponent();
	encryptionKeySecret_exponent.Encode(encryption_key_secret.data(), encryption_key_secret.size());
	
	ECDSA<ECP, IdentityHash<32>>::PublicKey encryptionKeyPublic;
	encryptionKeySecret.MakePublicKey(encryptionKeyPublic);
	
	const ECP::Point& encryptionKeyPublic_q = encryptionKeyPublic.GetPublicElement();
	encryptionKeyPublic_q.x.Encode(encryption_key_public.data() + 1, 32);
	encryptionKeyPublic_q.y.Encode(encryption_key_public.data() + 1 + encryptionKeyPublic_q.x.MinEncodedSize(), 32);
	
	

	ECDSA<ECP, IdentityHash<32>>::PrivateKey authenticationKeySecret;
	CryptoPP::Integer authenticationKeySecret_x;
	authenticationKeySecret_x.Decode(authentication_key_derivation.data(), SECRETKEYBYTES);

	authenticationKeySecret.Initialize(ASN1::secp256r1(), authenticationKeySecret_x);
	
	const Integer& authenticationKeySecret_exponent = authenticationKeySecret.GetPrivateExponent();
	authenticationKeySecret_exponent.Encode(authentication_key_secret.data(), authentication_key_secret.size());
	
	ECDSA<ECP, IdentityHash<32>>::PublicKey authenticationKeyPublic;
	authenticationKeySecret.MakePublicKey(authenticationKeyPublic);
	
	const ECP::Point& authenticationKeyPublic_q = authenticationKeyPublic.GetPublicElement();
	authenticationKeyPublic_q.x.Encode(authentication_key_public.data() + 1, 32);
	authenticationKeyPublic_q.y.Encode(authentication_key_public.data() + 1 + authenticationKeyPublic_q.x.MinEncodedSize(), 32);


    // set the silly public key leading byte
    main_key_public[0]          = 0x04;
    signing_key_public[0]       = 0x04;
    encryption_key_public[0]    = 0x04;
    authentication_key_public[0]= 0x04;

    // the vector of packets to generate
    std::vector<pgp::packet> packets;

    // allocate space for all the packets
    packets.reserve(8);

    // add the primary key packet
    packets.emplace_back(
        mpark::in_place_type_t<pgp::secret_key>{},                              // we are building a secret key
        creation,                                                               // created at
        pgp::key_algorithm::ecdsa,                                              // using the eddsa key algorithm
        mpark::in_place_type_t<pgp::secret_key::ecdsa_key_t>{},                 // key type
        std::forward_as_tuple(                                                  // public arguments
            pgp::curve_oid::ecdsa(),                                          	// curve to use
            pgp::multiprecision_integer{ std::move(main_key_public) }           // move in the public key point
        ),
        std::forward_as_tuple(                                                  // secret arguments
            pgp::multiprecision_integer{ std::move(main_key_secret) }           // move in the secret key point
        )
    );

    // add the user id packet
    packets.emplace_back(
       mpark::in_place_type_t<pgp::user_id>{},                                  // we are building a user id
       std::move(user)                                                          // for this user
    );

    // retrieve the main key and user id
    auto &main_key  = mpark::get<pgp::secret_key>(packets[0].body());
    auto &user_id   = mpark::get<pgp::user_id>(packets[1].body());

    // add self-signature for the key
    packets.emplace_back(
        mpark::in_place_type_t<pgp::signature>{},                               // we are making a signature
        main_key,                                                               // we sign with the main key
        user_id,                                                                // for this user
        pgp::signature_subpacket_set{{                                          // hashed subpackets
            pgp::signature_creation_time_subpacket  { signature  },             // signature was created at
            pgp::key_expiration_time_subpacket      { expiration },             // signature expires at
            pgp::key_flags_subpacket                { 0x01, 0x02 }              // used for certification and signing
        }},
        pgp::signature_subpacket_set{{                                          // unhashed subpackets
            pgp::issuer_subpacket{ main_key.fingerprint() }                     // fingerprint of the key we are signing with
        }}
    );

    // add the signing subkey
    packets.emplace_back(
        mpark::in_place_type_t<pgp::secret_subkey>{},                           // we are building a secret subkey
        creation,                                                               // created at
        pgp::key_algorithm::ecdsa,                                              // using the ecdsa key algorithm
        mpark::in_place_type_t<pgp::secret_key::ecdsa_key_t>{},                 // key type
        std::forward_as_tuple(                                                  // public arguments
            pgp::curve_oid::ecdsa(),                                          	// curve to use
            pgp::multiprecision_integer{ std::move(signing_key_public) }        // move in the public key point
        ),
        std::forward_as_tuple(                                                  // secret arguments
            pgp::multiprecision_integer{ std::move(signing_key_secret) }        // move in the secret key point
        )
    );

    // retrieve the newly created subkey
    auto &signing_key = mpark::get<pgp::secret_subkey>(packets.back().body());

    // now add a self-signature
    packets.emplace_back(
        mpark::in_place_type_t<pgp::signature>{},                               // subkey signature
        main_key,                                                               // we sign with the main key
        signing_key,                                                            // indicating we own this subkey
        pgp::signature_subpacket_set{{                                          // hashed subpackets
            pgp::signature_creation_time_subpacket  { signature  },             // signature created at
            pgp::key_expiration_time_subpacket      { expiration },             // signature expires at
            pgp::key_flags_subpacket                { 0x02 }              		// used for certification and signing
        }},
        pgp::signature_subpacket_set{{                                          // unhashed subpackets
            pgp::issuer_subpacket{ main_key.fingerprint() }                     // fingerprint of the signing key
        }}
    );

    // add the subkey for encryption
    packets.emplace_back(
        mpark::in_place_type_t<pgp::secret_subkey>{},                           // we are building a secret subkey
        creation,                                                               // created at
        pgp::key_algorithm::ecdh,                                               // using the ecdsa key algorithm
        mpark::in_place_type_t<pgp::secret_key::ecdh_key_t>{},                  // key type
        std::forward_as_tuple(                                                  // public arguments
            pgp::curve_oid::ecdsa(),                                      		// curve to use
            pgp::multiprecision_integer{ std::move(encryption_key_public) },    // move in the public key point
            pgp::hash_algorithm::sha256,                                        // use sha256 as hashing algorithm
            pgp::symmetric_key_algorithm::aes128                                // and aes128 as the symmetric key algorithm
        ),
        std::forward_as_tuple(                                                  // secret arguments
            pgp::multiprecision_integer{ std::move(encryption_key_secret) }     // move in the secret key point
        )
    );

    // retrieve the newly created subkey
    auto &encryption_key = mpark::get<pgp::secret_subkey>(packets.back().body());

    // now add a self-signature
    packets.emplace_back(
        mpark::in_place_type_t<pgp::signature>{},                               // subkey signature
        main_key,                                                               // we sign with the main key
        encryption_key,                                                         // indicating we own this subkey
        pgp::signature_subpacket_set{{                                          // hashed subpackets
            pgp::signature_creation_time_subpacket  { signature  },             // signature created at
            pgp::key_expiration_time_subpacket      { expiration },             // signature expires at
            pgp::key_flags_subpacket                { 0x04, 0x08 }              // used for encryption of communications and storage
        }},
        pgp::signature_subpacket_set{{                                          // unhashed subpackets
            pgp::issuer_subpacket{ main_key.fingerprint() }                     // fingerprint of the signing key
        }}
    );

    // add the authentication subkey
    packets.emplace_back(
        mpark::in_place_type_t<pgp::secret_subkey>{},                           // we are building a secret key
        creation,                                                               // created at
        pgp::key_algorithm::ecdsa,                                              // using the ecdsa key algorithm
        mpark::in_place_type_t<pgp::secret_key::ecdsa_key_t>{},                 // key type
        std::forward_as_tuple(                                                  // public arguments
            pgp::curve_oid::ecdsa(),                                          	// curve to use
            pgp::multiprecision_integer{ std::move(authentication_key_public) } // move in the public key point
        ),
        std::forward_as_tuple(                                                  // secret arguments
            pgp::multiprecision_integer{ std::move(authentication_key_secret) } // move in the secret key point
        )
    );

    // retrieve the new authentication subkey
    auto &authentication_key = mpark::get<pgp::secret_subkey>(packets.back().body());

    // and add a signature for that as well
    packets.emplace_back(
        mpark::in_place_type_t<pgp::signature>{},                               // subkey signature
        main_key,                                                               // we sign with the main key
        authentication_key,                                                     // indicating we own this subkey
        pgp::signature_subpacket_set{{                                          // hashed subpackets
            pgp::signature_creation_time_subpacket  { signature  },             // signature created at
            pgp::key_expiration_time_subpacket      { expiration },             // signature expires at
            pgp::key_flags_subpacket                { 0x20       }              // used for encryption of communications and storage 
        }},
        pgp::signature_subpacket_set{{                                          // unhashed subpackets
            pgp::issuer_subpacket{ main_key.fingerprint() }                     // fingerprint of the signing key
        }}
    );

    // return all the packets
    return packets;
}
