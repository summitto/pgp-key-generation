#!/usr/bin/env python3

import dataclasses, datetime, filecmp, re, os, random, subprocess, shutil, sys, tempfile, time
from dataclasses import dataclass
from typing import List, Tuple


def is_leap_year(year):
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)

def days_in_month(year, month):
    if month == 2:
        if is_leap_year(year): return 29
        else: return 28
    return [31, None, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]

# Convert a string date representation to a UNIX timestamp
def date_to_unix(string):
    return int(
        # parse the string into a datetime object
        datetime.datetime.strptime(string, "%Y-%m-%d %H:%M:%S")
        # tell it to consider itself a UTC time
            .replace(tzinfo = datetime.timezone.utc)
        # obtain the timestamp
            .timestamp()
    )


# Class hierarchy for randomly generating various kinds of data for input into
# the program
class Generate:
    def generate():
        raise NotImplementedError()

class GenerateString(Generate):
    def generate():
        length = random.randint(1, 200)
        return "".join([chr(random.randint(ord(' '), ord('~'))) for _ in range(length)])

class GenerateName(GenerateString):
    pass

class GenerateEmail(GenerateString):
    pass

class GenerateDate(Generate):
    def generate():
        while True:
            year = random.randint(1990, 2100)
            month = random.randint(1, 12)
            day = random.randint(1, days_in_month(year, month))
            hour = random.randint(0, 23)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            string = "{:04}-{:02}-{:02} {:02}:{:02}:{:02}".format(year, month, day, hour, minute, second)
            if date_to_unix(string) >= 1511740800:  # TODO: Change to variable date
                return string

class GenerateDatePair(Generate):
    def generate():
        while True:
            values = [GenerateDate.generate(), GenerateDate.generate()]
            #  if values[0] == values[1]:
            #      continue
            values.sort()
            return tuple(values)

class GenerateDie(Generate):
    def generate():
        return random.randint(1, 6)

class GenerateDice(Generate):
    def generate():
        length = 100 if random.randint(0, 1) == 0 else random.randint(100, 1000)
        return "".join(str(GenerateDie.generate()) for _ in range(length))

class GenerateSymmetricKey(GenerateString):
    pass

class GenerateInput():
    def generate():
        datepair = GenerateDatePair.generate()
        return {
            "name": GenerateName.generate(),
            "email": GenerateEmail.generate(),
            "creation": datepair[0],
            "expiration": datepair[1],
            "dice": GenerateDice.generate(),
            "key": GenerateSymmetricKey.generate(),
        }


# Specification for an execution of the program
@dataclass
class AppInput(Generate):
    key_type: str
    name: str
    email: str
    creation: str
    expiration: str
    dice: str
    key: str

    # Generate an input specification given a key type
    def generate(key_type):
        values = GenerateInput.generate()
        return AppInput(
            key_type,
            values["name"],
            values["email"],
            values["creation"],
            values["expiration"],
            values["dice"],
            values["key"]
        )


# A file name that is very unlikely to be chosen again in this same process
def safe_temporary_name():
    return "tmp_" + str(time.process_time()) + "_" + str(random.random()) + ".tmp"

# Create a new file with random bytes as content
def make_random_file(workdir, size):
    fname = os.path.join(workdir, safe_temporary_name())
    with open(fname, "wb") as f:
        f.write(bytes(random.choices(range(0, 256), k = size)))
    return fname


# Context manager for interacting with a process line-wise
class Application:
    # kwargs:
    # - stderr: either of:
    #     - None to send stderr to the terminal
    #     - subprocess.STDOUT to join stderr into stdout
    #     - subprocess.PIPE (internal, for subclasses)
    def __init__(self, exec_name, args, **kwargs):
        self._args = [exec_name] + args
        self._stderr = kwargs.get("stderr")
        self._line_filter = None

    def __enter__(self):
        self._proc = subprocess.Popen(
            self._args,
            stdin = subprocess.PIPE,
            stdout = subprocess.PIPE,
            stderr = self._stderr
        )
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        try:
            self._proc.wait(timeout = 1)
        except subprocess.TimeoutExpired:
            self._proc.kill()

    def write_data(self, data):
        self._proc.stdin.write(data)
        self._proc.stdin.flush()

    def write_line(self, line):
        if "\n" in line:
            raise Exception("Invalid newline in Application.write_line()")
        self._proc.stdin.write((line + "\n").encode("utf8"))
        self._proc.stdin.flush()

    def read_line(self, line, timeout_ms = 1000):
        while True:
            line = self._proc.stdout.read_line().decode("utf8")
            if line[-1] == "\n":
                line = line[:-1]
            if self._line_filter is None or self._line_filter(line):
                break
        return line

    def read_all(self):
        lines = self._proc.stdout.read().decode("utf8").split("\n")
        if self._line_filter is None:
            return "\n".join(lines)
        else:
            return "\n".join(line for line in lines if self._line_filter(line))

class KeygenApplication(Application):
    def __init__(self, exec_name, keyfile, appinput):
        args = [
            "-o", keyfile,
            "-t", appinput.key_type,
            "-n", appinput.name,
            "-e", appinput.email,
            "-s", appinput.creation,
            "-x", appinput.expiration
        ]
        super().__init__(exec_name, args)

class GPGApplication(Application):
    # kwargs:
    # - also_stderr: if True, join the stderr stream into the stdout stream. Incompatible with ignore_stderr.
    # - ignore_stderr: if True, pass stderr to /dev/null. Incompatible with also_stderr.
    # - gpg_homedir: if not None, directory to use as GPG homedir. If not given, uses a new temporary directory.
    def __init__(self, args, **kwargs):
        if kwargs.get("gpg_homedir") is not None:
            self._gpg_homedir = None
            self._gpg_homedir_name = kwargs.get("gpg_homedir")
        else:
            self._gpg_homedir = tempfile.TemporaryDirectory()
            self._gpg_homedir_name = self._gpg_homedir.name

        if kwargs.get("also_stderr") and kwargs.get("ignore_stderr"):
            raise Exception("Cannot pass both also_stderr and ignore_stderr to GPGApplication")

        if kwargs.get("also_stderr"):
            super().__init__("gpg", ["--homedir", self._gpg_homedir_name] + args, stderr = subprocess.STDOUT)
            self._line_filter = lambda line: re.match(r"^gpg: (keybox '.*' created|.*: trustdb created)$", line) is None

            self._gpg_should_grep = False
        elif kwargs.get("ignore_stderr"):
            super().__init__("gpg", ["--homedir", self._gpg_homedir_name] + args, stderr = subprocess.DEVNULL)

            self._gpg_should_grep = False
        else:
            super().__init__("gpg", ["--homedir", self._gpg_homedir_name] + args, stderr = subprocess.PIPE)

            self._gpg_should_grep = True

    def __enter__(self):
        super().__enter__()
        if self._gpg_should_grep:
            # Hack: filter out some unnecessary lines with grep
            subprocess.Popen(["grep", "-v", r"^gpg: \(keybox '.*' created\|.*: trustdb created\)$"], stdin = self._proc.stderr)
        return self

    def __exit__(self, *args):
        # If we created a temporary directory for the GPG homedir in __init__, clean it up here
        if self._gpg_homedir is not None:
            self._gpg_homedir.cleanup()

        super().__exit__(*args)

class Subpacket:
    pass

@dataclass
class SigCreatedSubpacket(Subpacket):
    date: str

@dataclass
class KeyExpirationSubpacket(Subpacket):
    expires: str

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
    algo: str
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


def parse_pgp_packet(filename):
    # Parse the packet stream using gpg
    with GPGApplication(["--list-packets", "--verbose", filename]) as app:
        output = app.read_all().split("\n")

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
                        elif part[0] == "algo": res.algo = part[1]
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

# Passes all keyword arguments on to GPGApplication.
def import_gpg_packet(filename, **kwargs):
    with GPGApplication(["--import", filename], also_stderr = True, **kwargs) as app:
        output = app.read_all().split("\n")

    l = [
        re.match(r'^gpg: key [0-9A-F]*: public key ".*" imported$', output[0]),
        re.match(r'^gpg: key [0-9A-F]*: secret key imported$', output[1]),
        re.match(r'^gpg: Total number processed: 1$', output[2]),
        re.match(r'^gpg:               imported: 1$', output[3]),
        re.match(r'^gpg:       secret keys read: 1$', output[4]),
        re.match(r'^gpg:   secret keys imported: 1$', output[5]),
    ]

    if not all(l):
        # for debugging
        print(l)

    return all(l)

# Passes all keyword arguments on to GPGApplication.
def sign_encrypt_file(keyid, message_fname, output_fname, **kwargs):
    # Remove the output file if it already exists
    if os.access(output_fname, os.F_OK):
        os.remove(output_fname)

    with GPGApplication([
                "--sign", "--encrypt",   # sign and encrypt
                "--local-user", keyid,   # using this key
                "-r", keyid,             # encrypt for the same key
                "-o", output_fname,      # write the result to this file
                "--trusted-key", keyid,  # trust our key (otherwise GPG won't encrypt for it)
                message_fname
            ], ignore_stderr = True, **kwargs) as app:
        # Ignore the output
        app.read_all()

    # The output file should now only exist if the operation succeeded
    return os.access(output_fname, os.F_OK)

# Passes all keyword arguments on to GPGApplication.
def decrypt_file(encrypted_fname, output_fname, **kwargs):
    # Remove the output file if it already exists
    if os.access(output_fname, os.F_OK):
        os.remove(output_fname)

    with GPGApplication(["--decrypt", "-o", output_fname, encrypted_fname], ignore_stderr = True, **kwargs) as app:
        # Ignore the output
        app.read_all()

    # The output file should now only exist if the operation succeeded
    return os.access(output_fname, os.F_OK)

# Use the specification to generate an initial key and its recovery seed
def generate_initial_key(workdir, exec_name, appinput):
    keyfile = os.path.join(workdir, safe_temporary_name())

    with KeygenApplication(exec_name, keyfile, appinput) as app:
        app.write_line("")  # generate a new key, no recovery seed
        app.write_line(appinput.dice)
        app.write_line(appinput.key)

        text = app.read_all()
        idx1 = text.find("write down the following recovery seed:")
        idx2 = text.rfind("write down the following recovery seed:")
        assert idx1 == idx2

        seed_start = text.find(":", idx1) + 2
        seed = text[seed_start:].split("\n")[0]

        return keyfile, seed

# Use the specification to regenerate the previous key from its recovery seed
def regenerate_key(workdir, exec_name, appinput, rec_seed):
    keyfile = os.path.join(workdir, safe_temporary_name())

    with KeygenApplication(exec_name, keyfile, appinput) as app:
        app.write_line(rec_seed)  # regenerate a previous key from a recovery seed
        app.write_line(appinput.key)  # with this symmetric key

        return keyfile


def report_error(appinput, keyfile):
    print(appinput)
    fname = "integration_test_keyfile_on_error_{}".format(int(time.time()))
    shutil.copy(keyfile, fname)
    print("Generated key file copied to '{}'".format(fname))

def run_test(exec_name, key_class):
    with tempfile.TemporaryDirectory() as tempdir:
        # --- Generate a new input set
        appinput = AppInput.generate(key_class)

        # --- Generate the key, and regenerate the key
        keyfile1, rec_seed = generate_initial_key(tempdir, exec_name, appinput)
        keyfile2 = regenerate_key(tempdir, exec_name, appinput, rec_seed)

        # --- Parse the keys using GPG and check equivalence
        parsed1 = parse_pgp_packet(keyfile1)
        parsed2 = parse_pgp_packet(keyfile2)
        # Note that this equality does what we want: the 'data' fields
        # of signatures are not included in the comparison.
        if parsed1 != parsed2:
            print("Key recovery didn't work")
            report_error(appinput, keyfile1)
            return False

        # --- Extract the main key id
        assert isinstance(parsed1[0], SecretKeyPacket)
        keyid = parsed1[0].keyid

        # --- Check sanity of the signature creation timestamp
        creation_stamp = date_to_unix(appinput.creation)

        for packet in parsed1:
            if isinstance(packet, SignaturePacket):
                if packet.created != creation_stamp:
                    print("Signature creation timestamp is incorrect")
                    print(packet.created)
                    print(creation_stamp)
                    report_error(appinput, keyfile1)
                    return False

        # --- Now we wish to perform more extensive testing on the
        #     generated key after it is imported, so we create a
        #     dedicated GPG homedir for gpg to store its state in
        with tempfile.TemporaryDirectory() as gpg_homedir:
            # --- Test importing a key
            if not import_gpg_packet(keyfile1, gpg_homedir = gpg_homedir):
                print("Key import didn't work")
                report_error(appinput, keyfile1)
                return False

            # --- Test signing and encrypting data
            message_fname = make_random_file(tempdir, 1000)
            output_fname = os.path.join(tempdir, safe_temporary_name())
            if not sign_encrypt_file(keyid, message_fname, output_fname, gpg_homedir = gpg_homedir):
                print("Sign+encrypt didn't work")
                report_error(appinput, keyfile1)
                return False

            # --- Test decrypting (and verifying) the file created above
            decrypt_fname = os.path.join(tempdir, safe_temporary_name())
            if not decrypt_file(output_fname, decrypt_fname, gpg_homedir = gpg_homedir):
                print("Decrypt didn't work")
                report_error(appinput, keyfile1)
                return False

            # --- Check whether decryption yielded the original file again
            if not filecmp.cmp(message_fname, decrypt_fname, shallow = False):
                print("Decryption produced a different file than was encrypted")
                report_error(appinput, keyfile1)
                return False

    return True


def main():
    if len(sys.argv) == 2:
        exec_name = sys.argv[1]
    else:
        print("Usage: {} <generate_derived_key executable>", file = sys.stderr)
        sys.exit(1)

    num_tests = 20
    key_classes = ["eddsa", "ecdsa", "rsa2048"]

    for key_class in key_classes:
        print("Running {} random tests for {}...".format(num_tests, key_class))

        for test_index in range(num_tests):
            if not run_test(exec_name, key_class):
                sys.exit(1)

    print("Succeeded!")

if __name__ == "__main__":
    main()
