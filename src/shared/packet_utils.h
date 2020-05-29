#pragma once

#include <pgp-packet/packet.h>
#include "parameters.h"


namespace packet_utils {

    /**
     *  Create a user id binding signature
     *
     *  @param user_id               The user id to bind to the key
     *  @param main_key              The key to sign the user id with
     *  @param signature_creation    The creation time of the signature
     *  @param signature_expiration  The expiration time of the signature
     *  @return The signature packet
     */
    pgp::packet user_id_signature(const pgp::user_id &user_id, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration);

    /**
     *  Create a subkey binding signature
     *
     *  @param type                  The key type of the bound subkey
     *  @param subkey                The key to bind give permissions and bind to the main key
     *  @param main_key              The key to sign the subkey with
     *  @param signature_creation    The creation time of the signature
     *  @param signature_expiration  The expiration time of the signature
     *  @return The signature packet
     */
    pgp::packet subkey_signature(parameters::key_type type, const pgp::secret_subkey &subkey, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration);

}
