#!/usr/bin/env python3

import argparse
import dataclasses, filecmp, re, os, random, shlex, shutil, subprocess, sys, tempfile, time
import datetime
from typing import List, Tuple
from generate import generateInput
from packet_parser import *
from dataclasses import dataclass


# Convert a string date representation to a UNIX timestamp
def date_to_unix(string):
    return int(
        # parse the string into a datetime object
        datetime.datetime.strptime(string, "%Y-%m-%d %H:%M:%S")
            # tell it to consider itself a UTC time
            .replace(tzinfo=datetime.timezone.utc)
            # obtain the timestamp
            .timestamp()
    )


class KeyFlag:
    Certification            = 0x01
    Signing                  = 0x02
    EncryptionCommunications = 0x04
    EncryptionStorage        = 0x08
    SplitKey                 = 0x10
    Authentication           = 0x20
    GroupKey                 = 0x80

# Specification for an execution of the program
@dataclass
class AppInput:
    key_type: str
    name: str
    email: str
    creation: str
    expiration: str
    dice: str
    key: str
    context: str
    key_creation: str

    # Generate an input specification given a key type
    def generate(key_type):
        values = generateInput()
        return AppInput(
            key_type,
            values["name"],
            values["email"],
            values["creation"],
            values["expiration"],
            values["dice"],
            values["key"],
            values["context"],
            values["key_creation"],
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

# Calls 'func' until it either returns a truthy value, or it has been called
# 'ntimes' times, whichever is first.
def retry_until_truthy(ntimes, func, description = ""):
    i = 0
    while True:
        i += 1
        ret = func()
        if ret or i >= ntimes:
            return ret
        print("retry_until_truthy({}): Retrying ({}/{}) on failure".format(description, i, ntimes), file = sys.stderr)


# Context manager for interacting with a process line-wise
class Application:
    # kwargs:
    # - stderr: either of:
    #     - None to send stderr to the terminal
    #     - subprocess.STDOUT to join stderr into stdout
    #     - subprocess.PIPE (internal, for subclasses)
    def __init__(self, exec_name, args, stderr=None):
        self._args = [exec_name] + args
        self._stderr = stderr
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
            print("Application: KILLED PROCESS in __exit__ due to timeout expiration", file = sys.stderr)
            print("  args: {}".format(self._args), file = sys.stderr)

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
    def __init__(self, exec_name, keyfile, appinput, debug_dump_keys=False):
        args = [
            "-o", keyfile,
            "-t", appinput.key_type,
            "-n", appinput.name,
            "-e", appinput.email,
            "-s", appinput.creation,
            "-x", appinput.expiration,
            "-k", appinput.context,
            "-c", appinput.key_creation
        ]

        if debug_dump_keys:
            args += ["--debug-dump-secret-and-public-keys"]

        super().__init__(exec_name, args)

class GPGApplication(Application):
    # kwargs:
    # - also_stderr: if True, join the stderr stream into the stdout stream. Incompatible with ignore_stderr.
    # - ignore_stderr: if True, pass stderr to /dev/null. Incompatible with also_stderr.
    # - gpg_homedir: if not None, directory to use as GPG homedir. If not given, uses a new temporary directory.
    def __init__(self, args, gpg_homedir=None, also_stderr=False, ignore_stderr=False):
        if gpg_homedir:
            self._gpg_homedir = None
            self._gpg_homedir_name = gpg_homedir
        else:
            self._gpg_homedir = tempfile.TemporaryDirectory()
            self._gpg_homedir_name = self._gpg_homedir.name

        if also_stderr and ignore_stderr:
            raise Exception("Cannot pass both also_stderr and ignore_stderr to GPGApplication")

        if also_stderr:
            super().__init__("gpg", ["--homedir", self._gpg_homedir_name] + args, stderr = subprocess.STDOUT)
            self._line_filter = lambda line: re.match(r"^gpg: (keybox '.*' created|.*: trustdb created)$", line) is None

            self._gpg_should_grep = False
        elif ignore_stderr:
            super().__init__("gpg", ["--homedir", self._gpg_homedir_name] + args, stderr=subprocess.DEVNULL)

            self._gpg_should_grep = False
        else:
            super().__init__("gpg", ["--homedir", self._gpg_homedir_name] + args, stderr=subprocess.PIPE)

            self._gpg_should_grep = True

    def __enter__(self):
        super().__enter__()
        if self._gpg_should_grep:
            # Hack: filter out some unnecessary lines with grep
            subprocess.Popen(["grep", "-v", r"^gpg: \(keybox '.*' created\|.*: trustdb created\)$"], stdin = self._proc.stderr)
        return self

    def __exit__(self, *args):
        super().__exit__(*args)

        # If we created a temporary directory for the GPG homedir in __init__, clean it up here
        if self._gpg_homedir is not None:
            self._gpg_homedir.cleanup()

def parse_pgp_packet(filename):
    # Parse the packet stream using gpg
    with GPGApplication(["--list-packets", "--verbose", filename]) as app:
        output = app.read_all().split("\n")

    # then parse gpg's output
    return parse_gpg_packet_listing(output)

# Passes all keyword arguments on to GPGApplication.
def import_gpg_packet(filename, **kwargs):
    with GPGApplication(["--import", filename], also_stderr=True, **kwargs) as app:
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
        print("OUTPUT FROM GPG WHEN IMPORTING:")
        print(output)

    return all(l)

# Passes all keyword arguments on to GPGApplication.
# Lists the fingerprints of all secret and public keys known to GPG with the
# given arguments.
def list_fingerprints(**kwargs):
    with GPGApplication(["--list-secret-keys", "--with-colons"], ignore_stderr=True, **kwargs) as app:
        output = [line.split(":") for line in app.read_all().split("\n")]

    # Return the last 16 bytes (the key id), because that's what the rest of
    # this script knows about.
    return [line[9][-16:] for line in output if line[0] == "fpr"]

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
            ], ignore_stderr=True, **kwargs) as app:
        # Ignore the output
        app.read_all()

    # The output file should now only exist if the operation succeeded
    return os.access(output_fname, os.F_OK)

# Passes all keyword arguments on to GPGApplication.
def decrypt_file(encrypted_fname, output_fname, **kwargs):
    # Remove the output file if it already exists
    if os.access(output_fname, os.F_OK):
        os.remove(output_fname)

    with GPGApplication(["--decrypt", "-o", output_fname, encrypted_fname], ignore_stderr=True, **kwargs) as app:
        # Ignore the output
        app.read_all()

    # The output file should now only exist if the operation succeeded
    return os.access(output_fname, os.F_OK)

# Use the specification to generate an initial key and its recovery seed
def generate_initial_key(workdir, exec_name, appinput):
    keyfile = os.path.join(workdir, safe_temporary_name())

    with KeygenApplication(exec_name, keyfile, appinput, debug_dump_keys=True) as app:
        app.write_line("")  # generate a new key, no recovery seed
        app.write_line(appinput.dice)
        app.write_line("yes")
        app.write_line(appinput.key)

        text = app.read_all()
        idx1 = text.find("write down the following recovery seed:")
        idx2 = text.rfind("write down the following recovery seed:")
        assert idx1 == idx2

        seed_start = text.find(":", idx1) + 2
        seed = text[seed_start:].split("\n")[0]

        param_match = re.search(r"COMPUTED KEYS:\n(- [^\n]*\n)*", text)
        if not param_match:
            raise ValueError("Can't find COMPUTED KEYS in", text)

        param_lines = param_match[0].split("\n")[1:-1]
        param_dict = {keytype: params
                      for [keytype, params] in [line[2:].split(": ") for line in param_lines]}

        return keyfile, seed, param_dict

# Use the specification to regenerate the previous key from its recovery seed
def regenerate_key(workdir, exec_name, appinput, rec_seed):
    keyfile = os.path.join(workdir, safe_temporary_name())

    with KeygenApplication(exec_name, keyfile, appinput) as app:
        app.write_line(rec_seed)  # regenerate a previous key from a recovery seed
        app.write_line(appinput.key)  # with this symmetric key

        # Ignore the output
        app.read_all()

    return keyfile

def check_params_against_parsed(params, parsed):
    def sig_key_flags(sig):
        if not isinstance(sig, SignaturePacket):
            print("Expected signature packet after secret subkey packet")
            return None
        subs = [pkt for pkt in sig.hashed_subs if isinstance(pkt, KeyFlagsSubpacket)]
        if len(subs) != 1:
            print("Expected key flags subpacket in signature packet")
            return None
        return subs[0].flags

    def perform_check(pub_param, sec_param, pkt):
        def normalise_value(value):
            return re.sub(r"^0*", "", value.lower())

        def check_in_list(typ, idx, value):
            value = normalise_value(value)
            gpgvalue = normalise_value(
                            [data for (t, i, data) in pkt.keys if (t, i) == (typ, idx)][0])
            if gpgvalue != value:
                print("In checking debug-printed parameters against GPG parsed values:")
                print("Tag {} {} has value:".format(typ, idx))
                print(gpgvalue)
                print("But should have had value:")
                print(value)
            return gpgvalue == value

        def key_value_parse(s):
            return {var: value
                    for [var, value] in [part.split("=") for part in s.split(" ")]}

        if pkt.algo == 1:  # RSA
            pub_param_dict = key_value_parse(pub_param)
            sec_param_dict = key_value_parse(sec_param)
            return (check_in_list("pkey", 0, pub_param_dict["n"]) and
                    check_in_list("pkey", 1, pub_param_dict["e"]) and
                    check_in_list("skey", 2, sec_param_dict["d"]) and
                    check_in_list("skey", 3, sec_param_dict["p"]) and
                    check_in_list("skey", 4, sec_param_dict["q"]) and
                    check_in_list("skey", 5, sec_param_dict["u"]))
        elif pkt.algo == 18:  # ECDH
            return check_in_list("pkey", 1, pub_param) and check_in_list("skey", 3, sec_param)
        elif pkt.algo == 19:  # ECDSA
            return check_in_list("pkey", 1, pub_param) and check_in_list("skey", 2, sec_param)
        elif pkt.algo == 22:  # EDDSA
            return check_in_list("pkey", 1, pub_param) and check_in_list("skey", 2, sec_param)
        else:
            print("Unsupported key algorithm {} in secret key packet".format(pkt.algo))
            return False

    seckeys = {"main": parsed[0]}

    # start at 1 to skip the main key
    i = 1
    while i < len(parsed):
        if isinstance(parsed[i], SecretKeyPacket):
            flags = sig_key_flags(parsed[i + 1])
            if flags is None:
                return False
            elif flags == KeyFlag.Certification | KeyFlag.Signing:
                seckeys["signing"] = parsed[i]
            elif flags == KeyFlag.EncryptionCommunications | KeyFlag.EncryptionStorage:
                seckeys["encryption"] = parsed[i]
            elif flags == KeyFlag.Authentication:
                seckeys["authentication"] = parsed[i]
            i += 2
        else:
            i += 1

    kinds = ["main", "signing", "encryption", "authentication"]
    if not all(k in seckeys for k in kinds):
        print("Expected main, signing, encryption and authentication keys in packet listing")
        print("Actual:", kinds)
        return False

    for kind in kinds:
        if not perform_check(params[kind + " public"], params[kind + " secret"], seckeys[kind]):
            return False

    return True


def report_error(appinput, keyfile, rec_seed):
    print(appinput)
    print("Command line: -t {} -n {} -e {} -s {} -x {} -k {} -c {}".format(
        *(shlex.quote(x) for x in
            [appinput.key_type, appinput.name, appinput.email, appinput.creation,
            appinput.expiration, appinput.context, appinput.key_creation])
    ))
    print("Dice: {}".format(appinput.dice))
    print("Encryption key: {}".format(appinput.key))
    print("Recovery seed: {}".format(rec_seed))
    fname = "integration_test_keyfile_on_error_{}".format(int(time.time()))
    shutil.copy(keyfile, fname)
    print("Generated key file copied to '{}'".format(fname))

def run_test(exec_name, key_class):
    with tempfile.TemporaryDirectory() as tempdir:
        # --- Generate a new input set
        appinput = AppInput.generate(key_class)

        # --- Generate the key, and regenerate the key
        keyfile1, rec_seed, key_param_dict = generate_initial_key(tempdir, exec_name, appinput)
        keyfile2 = regenerate_key(tempdir, exec_name, appinput, rec_seed)

        # --- Parse the keys using GPG and check equivalence
        parsed1 = parse_pgp_packet(keyfile1)
        parsed2 = parse_pgp_packet(keyfile2)
        # Note that this equality does what we want: the 'data' fields
        # of signatures are not included in the comparison.
        if parsed1 != parsed2:
            print("Key recovery didn't work")
            report_error(appinput, keyfile1, rec_seed)
            return False

        # --- Check whether the PGP packet library correctly passed on the
        #     parameters to GPG
        if not check_params_against_parsed(key_param_dict, parsed1):
            print("Generated parameters are not equal to those imported into GPG")
            report_error(appinput, keyfile1, rec_seed)
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
                    report_error(appinput, keyfile1, rec_seed)
                    return False

        # --- Now we wish to perform more extensive testing on the
        #     generated key after it is imported, so we create a
        #     dedicated GPG homedir for gpg to store its state in
        all_keyids = [packet.keyid for packet in parsed1 if isinstance(packet, SecretKeyPacket)]
        with tempfile.TemporaryDirectory() as gpg_homedir:
            # --- Test importing a key
            if not import_gpg_packet(keyfile1, gpg_homedir = gpg_homedir):
                print("Key import didn't work")
                report_error(appinput, keyfile1, rec_seed)
                return False

            fprs_in_listing = list_fingerprints(gpg_homedir = gpg_homedir)
            while any(k not in fprs_in_listing for k in all_keyids):
                print("Some keyid in {} not found in gpg listing yet!".format(all_keyids))
                fprs_in_listing = list_fingerprints(gpg_homedir = gpg_homedir)

            # --- Test signing and encrypting data
            message_fname = make_random_file(tempdir, 1000)
            output_fname = os.path.join(tempdir, safe_temporary_name())
            if not sign_encrypt_file(keyid, message_fname, output_fname, gpg_homedir = gpg_homedir):
                print("Sign+encrypt didn't work")
                report_error(appinput, keyfile1, rec_seed)
                return False

            # --- Test decrypting (and verifying) the file created above
            decrypt_fname = os.path.join(tempdir, safe_temporary_name())
            # This retrying is sometimes necessary; I suspect that it is because the GPG agent
            # doesn't get up soon enough, so the private key material is not available. No proof
            # though.
            if not retry_until_truthy(2, lambda: decrypt_file(output_fname, decrypt_fname, gpg_homedir = gpg_homedir), "decrypt_file"):
                print("Decrypt didn't work")
                report_error(appinput, keyfile1, rec_seed)
                return False

            # --- Check whether decryption yielded the original file again
            if not filecmp.cmp(message_fname, decrypt_fname, shallow = False):
                print("Decryption produced a different file than was encrypted")
                report_error(appinput, keyfile1, rec_seed)
                return False

    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("exec_name", help="generate_derived_key executable")
    parser.add_argument("-n", "--num_tests", required=False, type=int, default=200,
                        help="Number of repetitions to run for the tests.")

    args = parser.parse_args()
    exec_name = args.exec_name
    num_tests = args.num_tests

    key_classes = ["eddsa", "ecdsa", "rsa2048", "rsa4096", "rsa8192"]

    for key_class in key_classes:
        print("Running {} random tests for {}...".format(num_tests, key_class))

        for test_index in range(num_tests):
            if not run_test(exec_name, key_class):
                sys.exit(1)

    print("Succeeded!")


if __name__ == "__main__":
    main()
