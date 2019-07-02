#!/usr/bin/env python3

import dataclasses, filecmp, re, os, random, subprocess, shutil, sys, tempfile, time
from dataclasses import dataclass
from typing import List, Tuple

from date_utils import *
from generate import *
from packet_parser import *


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

def gracefully_terminate(proc):
    proc.terminate()
    try:
        proc.wait(timeout = 1)
    except subprocess.TimeoutExpired:
        proc.kill()
        assert proc.wait() is not None

class SSHD:
    def __init__(self):
        self._tempdir = tempfile.TemporaryDirectory()
        self._tempdir_name = self._tempdir.name

        self._port = 2222
        self._config_file = os.path.join(self._tempdir_name, "sshd_config")
        self._auth_keys_file = os.path.join(self._tempdir_name, "authorized_keys")
        self._host_key_file = os.path.join(self._tempdir_name, "ssh_host_rsa_key")

        # Create the authorized_keys file so that we can set its permissions to 600
        with open(self._auth_keys_file, "w") as f: pass
        os.chmod(self._auth_keys_file, 0o600)

    def __enter__(self):
        # Write the sshd_config file
        with open(self._config_file, "w") as f:
            f.write("""Port {}
AuthorizedKeysFile {}
ChallengeResponseAuthentication no
PasswordAuthentication no
UsePAM no
HostKey {}
ForceCommand true
StrictModes no
""".format(self._port, self._auth_keys_file, self._host_key_file))

        # Generate the host key
        subprocess.check_call(["ssh-keygen", "-t", "rsa", "-N", "", "-f", self._host_key_file])

        # Start sshd
        self._proc = subprocess.Popen(["/usr/bin/sshd", "-ddd", "-f", self._config_file], stderr = open("sshd_output.txt", "w"))

        return self

    def __exit__(self, *args):
        gracefully_terminate(self._proc)
        self._tempdir.cleanup()

    def set_authorized_key(self, key_string):
        with open(self._auth_keys_file, "w") as f:
            f.write(key_string + "\n")
        print("### file " + self._auth_keys_file + " contains '" + key_string + "'")

    def port(self):
        return self._port

    def host_key_entry(self):
        with open(self._host_key_file + ".pub") as f:
            return "127.0.0.1 " + f.read().strip()

class GPGAgent:
    def __init__(self, homedir):
        self._homedir = homedir

    def __enter__(self):
        self._proc = subprocess.Popen(["gpg-agent", "--homedir", self._homedir, "--daemon"])

    def __exit__(self, *args):
        gracefully_terminate(self._proc)


def parse_pgp_packet(filename):
    # Parse the packet stream using gpg
    with GPGApplication(["--list-packets", "--verbose", filename]) as app:
        output = app.read_all().split("\n")

    # then parse gpg's output
    return parse_gpg_packet_listing(output)

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

# Passes all keyword arguments on to GPGApplication.
def export_ssh_authorized_key(keyid, **kwargs):
    with GPGApplication(["--export-ssh-key", keyid], **kwargs) as app:
        return app.read_all().strip()

# Passes all keyword arguments on to GPGApplication.
def export_gpg_secret_key(keyid, **kwargs):
    with GPGApplication(["--armor", "--export-secret-key", keyid], **kwargs) as app:
        return app.read_all()

# Passes all keyword arguments on to GPGApplication.
def get_keygrip(keyid, **kwargs):
    with GPGApplication(["--list-keys", "--with-colons", "--with-keygrip", keyid], **kwargs) as app:
        output = app.read_all()

    current_id = None

    for line in output.split("\n"):
        if len(line) == 0:
            continue

        fields = line.split(":")
        if fields[0] == "pub" or fields[0] == "sub":
            # Field 4 is the key ID
            current_id = fields[4]
        elif fields[0] == "grp":
            if current_id == keyid:
                # Field 9 is the keygrip
                return fields[9]

    return None

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

def run_test(exec_name, key_class, sshd):
    with tempfile.TemporaryDirectory() as tempdir:
        # --- Ensure that the temporary directory is only rwx by us
        os.chmod(tempdir, 0o700)

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
            # We also need a GPG agent in that directory
            with GPGAgent(gpg_homedir):
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

                # --- Now test the authentication subkey.
                # Find the authentication subkey
                auth_keyid = find_key_with_flags(parsed1, 0x20)
                if auth_keyid is None:
                    print("No purely-authentication subkey found")
                    report_error(appinput, keyfile1)
                    return False

                # Inform gpg-agent that this authentication subkey should be used for SSH authentication
                auth_keygrip = get_keygrip(auth_keyid, gpg_homedir = gpg_homedir)
                with open(os.path.join(gpg_homedir, "sshcontrol"), "w") as f:
                    f.write(auth_keygrip + "\n")

                # Get the name of the socket that gpg-agent listens on for SSH authentication
                ssh_auth_sock = subprocess.check_output(["gpgconf", "--homedir", gpg_homedir, "--list-dirs", "agent-ssh-socket"]) \
                                          .strip()

                print("### ssh_auth_sock = {}".format(ssh_auth_sock))

                # Export the ssh key using gpg and authorize it in the sshd daemon
                # (note that this automatically selects the authentication subkey)
                ssh_authorized_key_string = export_ssh_authorized_key(keyid, gpg_homedir = gpg_homedir)
                sshd.set_authorized_key(ssh_authorized_key_string)

                # Get the host key and write it to a file
                ssh_host_key_entry = sshd.host_key_entry()
                ssh_known_hosts_name = os.path.join(tempdir, safe_temporary_name())
                with open(ssh_known_hosts_name, "w") as f: f.write(ssh_host_key_entry + "\n")

                # Try logging in
                try:
                    ssh_env = os.environ.copy()
                    ssh_env["SSH_AUTH_SOCK"] = ssh_auth_sock
                    subprocess.check_call(["ssh", "-vv", "-o", "CheckHostIP=no", "-o", "UserKnownHostsFile=" + ssh_known_hosts_name, "-p", str(sshd.port()), "127.0.0.1"], env = ssh_env)
                except subprocess.CalledProcessError:
                    print("ssh failed, possibly due to invalid authentication subkey?")
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

    with SSHD() as sshd:
        for key_class in key_classes:
            print("Running {} random tests for {}...".format(num_tests, key_class))

            for test_index in range(num_tests):
                if not run_test(exec_name, key_class, sshd):
                    sys.exit(1)

    print("Succeeded!")

if __name__ == "__main__":
    main()
