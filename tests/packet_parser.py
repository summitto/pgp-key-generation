import dataclasses, re
from dataclasses import dataclass
from typing import List, Tuple


class Subpacket:
    pass

@dataclass
class SigCreatedSubpacket(Subpacket):
    date: str

@dataclass
class KeyExpirationSubpacket(Subpacket):
    expires: str

@dataclass
class PreferredSymmetricKeyAlgorithmsSubpacket(Subpacket):
    algorithms: str

@dataclass
class KeyFlagsSubpacket(Subpacket):
    flags: int

@dataclass
class IssuerSubpacket(Subpacket):
    issuer: str

@dataclass
class IssuerFingerprintSubpacket(Subpacket):
    issuerFingerprint: str

@dataclass
class PrimaryKeyBindingSubpacket(Subpacket):
    sigclass: int
    algo: int
    digestalgo: int


class Packet:
    pass

@dataclass
class SecretKeyPacket(Packet):
    version: int
    algo: int
    created: int
    expires: int
    keys: List[Tuple[str, int, str]]
    checksum: str
    keyid: str

@dataclass
class UserIDPacket(Packet):
    userid: str

@dataclass
class SignaturePacket(Packet):
    algo: int
    keyid: str
    version: int
    created: int
    md5len: int
    sigclass: int
    digest: Tuple[int, str]
    hashed_subs: List[Subpacket]
    unhashed_subs: List[Subpacket]
    # Do not compare the data fields, because the actual signature data does
    # not need to be deterministic -- thus equality of that data is not really
    # informative
    datas: List[str] = dataclasses.field(compare = False)


def parse_gpg_packet_listing(output):
    # Ignore the offset comments
    output = [line for line in output if not line.startswith("#")]
    # Where are we currently in the output
    cursor = 0

    # First a :type: line with possible extra text, then an indented block
    # This updates the 'cursor' variable in this scope
    # Returns: (type, extra text, [block lines])
    def read_packet():
        nonlocal cursor

        match = re.match(r"^:([^:]*):(.*)$", output[cursor])
        assert match is not None

        cursor += 1

        lines = []
        while cursor < len(output) and output[cursor][:1].isspace():
            lines.append(output[cursor].lstrip())
            cursor += 1

        return match.group(1), match.group(2), lines

    # Returns the subpacket parsed
    def parse_subpacket(typeid, text):
        if typeid == 2:  # sig created
            match = re.match(r"^sig created (.*)$", text)
            return SigCreatedSubpacket(match.group(1))
        elif typeid == 9:  # key expires
            match = re.match(r"^key expires after (.*)$", text)
            return KeyExpirationSubpacket(match.group(1))
        elif typeid == 11:  # preferred symmetric key algorithms
            match = re.match(r"^pref-sym-algos: (.*)$", text)
            return PreferredSymmetricKeyAlgorithmsSubpacket(match.group(1))
        elif typeid == 27:  # key flags
            match = re.match(r"^key flags: (.*)$", text)
            return KeyFlagsSubpacket(int(match.group(1), 16))
        elif typeid == 16:  # issuer
            match = re.match(r"^issuer key ID (.*)$", text)
            return IssuerSubpacket(match.group(1))
        elif typeid == 32:  # primary key binding (signature)
            match = re.match(r"^signature: v4, class ([^,]*), algo ([^,]*), digest algo (.*)$", text)
            return PrimaryKeyBindingSubpacket(int(match.group(1), 16), int(match.group(2)), int(match.group(3)))
        elif typeid == 33:  # issuer fingerprint
            match = re.match(r"^issuer fpr v4 (.*)$", text)
            return IssuerFingerprintSubpacket(match.group(1))
        else:
            raise Exception("Unrecognised subpacket id " + str(typeid))

    # Returns the packet parsed
    def interpret_packet(typestr, extra_text, block_lines):
        if typestr == "secret key packet" or typestr == "secret sub key packet":
            res = SecretKeyPacket(-1, "", -1, -1, [], "", "")

            for line in block_lines:
                if line.startswith("version"):
                    for part in line.split(","):
                        part = part.strip().split(" ")
                        if part[0] == "version": res.version = int(part[1])
                        elif part[0] == "algo": res.algo = int(part[1])
                        elif part[0] == "created": res.created = int(part[1])
                        elif part[0] == "expires": res.expires = int(part[1])
                elif line.startswith("pkey") or line.startswith("skey"):
                    match = re.match(r"^([^[]*)\[([^]]*)\]: (.*)$", line)
                    assert match is not None
                    res.keys.append((match.group(1), int(match.group(2)), match.group(3)))
                elif line.startswith("checksum"):
                    res.checksum = line.split(" ")[1]
                elif line.startswith("keyid"):
                    res.keyid = line.split(" ")[1]
                else:
                    raise Exception("Unrecognised line in packet")

            return res

        elif typestr == "user ID packet":
            return UserIDPacket(extra_text[1:-1])

        elif typestr == "signature packet":
            res = SignaturePacket(-1, "", -1, -1, -1, -1, (-1, ""), [], [], [])

            for line in block_lines:
                if line.startswith("version"):
                    for part in (line + ", " + extra_text).split(","):
                        part = part.strip().split(" ")
                        if part[0] == "version": res.version = int(part[1])
                        elif part[0] == "created": res.created = int(part[1])
                        elif part[0] == "md5len": res.md5len = int(part[1])
                        elif part[0] == "sigclass": res.sigclass = int(part[1], 16)
                        elif part[0] == "algo": res.algo = int(part[1])
                        elif part[0] == "keyid": res.keyid = part[1]
                elif line.startswith("digest"):
                    match = re.match(r"^digest algo (.*), begin of digest (.*)$", line)
                    res.digest = (int(match.group(1)), match.group(2))
                elif line.startswith("hashed subpkt") or line.startswith("subpkt"):
                    match = re.match(r"^(?:hashed )?subpkt ([^ ]*) len (?:[^ ]*) \((.*)\)$", line)
                    res.hashed_subs.append(parse_subpacket(int(match.group(1)), match.group(2)))
                elif line.startswith("data"):
                    match = re.match(r"^data: (.*)$", line)
                    res.datas.append(match.group(1))
                else:
                    raise Exception("Unrecognised line in packet")

            return res

        else:
            raise Exception("Unrecognised packet type '" + typestr + "'")

    packets = []
    while cursor < len(output):
        if len(output[cursor]) == 0:
            cursor += 1
            continue
        packets.append(interpret_packet(*read_packet()))

    return packets
