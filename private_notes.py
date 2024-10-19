#Jeffrey Zhu & Shane Li
import os
import pickle
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class PrivNotes:
    MAX_NOTE_LEN = 2048

    def __init__(self, password, data=None, checksum=None):
        """Constructor.
        
        Args:
        password (str) : password for accessing the notes
        data (str) [Optional] : a hex-encoded serialized representation to load
                                (defaults to None, which initializes an empty notes database)
                                First 24 hex values: current nonce
                                Next 32 hex values: salt
                                Everything else: data
        checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                    possible rollback attacks (defaults to None, in which
                                    case, no rollback protection is guaranteed)

        Raises:
        ValueError : malformed serialized format or authentication failure
        """
        self.kvs = {}
        # Derive the key once with PBKDF2
        if data is None:
            #Set the nonce counter used when dumping to 0
            self.nonce = 0
            self.salt = os.urandom(16)
        else: 
            self.nonce = int(data[:24], 16)
            self.salt = bytes.fromhex(data[24:56])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=200000,
            backend=default_backend()
        )
        self.key = kdf.derive(bytes(password, 'ascii'))
        if data is not None:
            # Load and decrypt the database
            self.nonce = int(data[:24], 16)
            self.salt = bytes.fromhex(data[24:56])
            c = hmac.new(self.key, bytes(data, 'ascii'), digestmod='sha256').hexdigest()
            if c != checksum:
                raise ValueError("Checksum mismatch! Potential rollback attack detected.")

            # Extract encrypted data
            encrypted_data = bytes.fromhex(data[56:])
            try:
                decrypted_data = self._decrypt(self.nonce, encrypted_data, 'dump', False)
                self.kvs = pickle.loads(decrypted_data)
            except Exception:
                raise ValueError("Authentication failed! Invalid password or corrupted data.")
            self.nonce += 1
            #The Global Nonce is updated
    def dump(self):
        """Computes a serialized representation of the notes database
        together with a checksum.
        
        Returns: 
        data (str) : a hex-encoded serialized representation of the contents of the notes
                    database (that can be passed to the constructor)
        checksum (str) : a hex-encoded checksum for the data used to protect
                        against rollback attacks (up to 64 characters in length)
        """
        #Nonce = first 8 bytes, salt = 16 bytes after, data after
        serialized_data = self.nonce.to_bytes(12, 'big').hex() + self.salt.hex()
        encrypted_data = self._encrypt(pickle.dumps(self.kvs), 'dump',False)[1]
        serialized_data += encrypted_data.hex()

        # Compute HMAC-SHA256 checksum
        checksum = hmac.new(self.key, bytes(serialized_data, 'ascii'), digestmod='sha256').hexdigest()

        return serialized_data, checksum

    def get(self, title):
        """Fetches the note associated with a title.
        
        Args:
        title (str) : the title to fetch
        
        Returns: 
        note (str) : the note associated with the requested title if
                    it exists, and otherwise None
        """
        hkey = hmac.new(self.key, bytes(title, 'ascii'), digestmod='sha256').hexdigest()
        if hkey in self.kvs:
            try:
                encrypted_note = self.kvs[hkey]
            except Exception:
                raise ValueError("Title and Note MisMatch! Potential Swap Attack detected.")
            return self._decrypt(encrypted_note[0], encrypted_note[1], title).decode('ascii')
        return None

    def set(self, title, note):
        """Associates a note with a title and adds it to the database
        (or updates the associated note if the title is already
        present in the database).
        
        Args:
            title (str) : the title to set
            note (str) : the note associated with the title

        Returns:
            None

        Raises:
            ValueError : if note length exceeds the maximum
        """
        if len(note) > self.MAX_NOTE_LEN:
            raise ValueError('Maximum note length exceeded')

        # Generate a unique key for the note using HMAC-SHA256
        hkey = hmac.new(self.key, bytes(title, 'ascii'), digestmod='sha256').hexdigest()

        # Encrypt the note using AES-GCM
        nonce, ciphertext = self._encrypt(bytes(note, 'ascii'), title)

        # Store the encrypted note
        self.kvs[hkey] = nonce, ciphertext

    def remove(self, title):
        """Removes the note for the requested title from the database.
        
        Args:
            title (str) : the title to remove

        Returns:
            success (bool) : True if the title was removed and False if the title was
                            not found
        """
        hkey = hmac.new(self.key, bytes(title, 'ascii'), digestmod='sha256').hexdigest()
        if hkey in self.kvs:
            del self.kvs[hkey]
            return True
        return False
    def _pad(self, plaintext):
        """Pads the plaintext to the fixed length of 2048 bytes."""
        if len(plaintext) > self.MAX_NOTE_LEN:
            raise ValueError('Note exceeds maximum length of 2048 bytes')
        padding_length = self.MAX_NOTE_LEN - len(plaintext)
        return plaintext + b'\x00' * padding_length  # Pad with null bytes

    def _unpad(self, padded_plaintext):
        """Removes padding (trailing null bytes)."""
        return padded_plaintext.rstrip(b'\x00')
    
    def _encrypt(self, plaintext, AD: str, noteEncryption = True):
        """Encrypt the plaintext with a nonce based on the title (nonce_source)
        
        Args:
            plaintext (bytes): the note to encrypt
            AD
            noteEncryption (bool): Checks whether or not we are encrypting for notes, in which case, we'll check the max note size and pad.

        Returns:
            Corresponding nonce as an int, ciphertext
        """
        #Adds padding to the plaintext, up to the max len of 2048 bytes
        if(noteEncryption):
            plaintext = self._pad(plaintext)
        
        nonce = self.nonce.to_bytes(12, 'big')
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, bytes(str(AD), 'ascii'))
        
        #Increment the nonce for the next encryption
        self.nonce += 1
        return int.from_bytes(nonce), ciphertext

    def _decrypt(self, nonce, ciphertext, AD, noteEncryption = True):
        """Decrypt the ciphertext deterministically based on nonce_source, the title.
        
        Args:
            nonce: the value of the nonce
            ciphertext (bytes): the ciphertext to decrypt
            AD: Associated data
            noteEncryption (bool): Checks whether or not we are decrypting for notes, in which case, we'll check the max note size and pad

        Returns:
            bytes: the decrypted data
        """
        aesgcm = AESGCM(self.key)
        nonce = nonce.to_bytes(12, 'big')
        plaintext = aesgcm.decrypt(nonce, ciphertext, bytes(str(AD), 'ascii'))

        if noteEncryption:
            return self._unpad(plaintext)

        return plaintext