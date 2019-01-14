#pragma once

#include <boost/utility/string_view.hpp>
#include <pgp-packet/packet.h>
#include "master_key.h"
#include <ctime>


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
std::vector<pgp::packet> generate_key(const master_key &master, std::string user, uint32_t creation, uint32_t signature, uint32_t expiration, boost::string_view context);
