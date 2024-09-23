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
          checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                      possible rollback attacks (defaults to None, in which
                                      case, no rollback protection is guaranteed)

        Raises:
          ValueError : malformed serialized format or authentication failure
        """
        self.kvs = {}

        # Derive the key once with PBKDF2
        if data is None:
            self.salt = os.urandom(16)
        else: 
            self.salt = bytes.fromhex(data[:32])
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

            c = hmac.new(self.key, bytes(data, 'ascii'), digestmod='sha256').hexdigest()
            if c != checksum:
                raise ValueError("Checksum mismatch! Potential rollback attack detected.")

            # Extract encrypted data
            encrypted_data = bytes.fromhex(data[32:])
            try:
                decrypted_data = self._decrypt(self.salt, encrypted_data, False)
                self.kvs = pickle.loads(decrypted_data)
            except Exception:
                raise ValueError("Authentication failed! Invalid password or corrupted data.")

        else:
            # Initialize empty notes database for new instance
            self.kvs = {}

    def dump(self):
        """Computes a serialized representation of the notes database
           together with a checksum.
        
        Returns: 
          data (str) : a hex-encoded serialized representation of the contents of the notes
                       database (that can be passed to the constructor)
          checksum (str) : a hex-encoded checksum for the data used to protect
                           against rollback attacks (up to 64 characters in length)
        """
        serialized_data = self.salt.hex() + self._encrypt(self.salt, pickle.dumps(self.kvs), False).hex()

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
            return self._decrypt(bytes(title, 'ascii'), encrypted_note).decode('ascii')
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

        # Encrypt the note using AES-GCM (nonce derived from title)
        encrypted_note = self._encrypt(bytes(title, 'ascii'), bytes(note, 'ascii'))

        # Store the encrypted note
        self.kvs[hkey] = encrypted_note

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
    
    def _encrypt(self, nonce_source, plaintext, noteEncryption = True):
        """Encrypt the plaintext with a nonce based on the title (nonce_source)
        
        Args:
            nonce_source (bytes): The source of the nonce, which in this case, is the title
            plaintext (bytes): the note to encrypt
            noteEncryption (bool): Checks whether or not we are encrypting for notes, in which case, we'll check the max note size and pad.

        Returns:
            bytes: the encrypted data
        """
        #Adds padding to the plaintext, up to the max len of 2048 bytes
        if(noteEncryption):
            new_plaintext = self._pad(plaintext)
        else:
            new_plaintext = plaintext
        
        nonce = hashes.Hash(hashes.SHA256(), backend=default_backend())
        nonce.update(nonce_source)
        nonce_value = nonce.finalize()[:12]  # 12 bit nonce for AES-GCM

        aesgcm = AESGCM(self.key)
        return aesgcm.encrypt(nonce_value, new_plaintext, nonce_source)

    def _decrypt(self, nonce_source, ciphertext, noteEncryption = True):
        """Decrypt the ciphertext deterministically based on nonce_source, the title.
        
        Args:
            nonce_source (bytes): the source of the nonce (e.g., the title)
            ciphertext (bytes): the ciphertext to decrypt
            noteEncryption (bool): Checks whether or not we are decrypting for notes, in which case, we'll check the max note size and pad

        Returns:
            bytes: the decrypted data
        """
        # Derive a deterministic 12-byte nonce from nonce_source (e.g., title)
        nonce = hashes.Hash(hashes.SHA256(), backend=default_backend())
        nonce.update(nonce_source)
        nonce_value = nonce.finalize()[:12]  # AES-GCM requires a 12-byte nonce

        aesgcm = AESGCM(self.key)

        new_plaintext = aesgcm.decrypt(nonce_value, ciphertext, nonce_source)

        if noteEncryption:
            return self._unpad(new_plaintext)
        else:
            return new_plaintext
        # Returning nonce_source (title) allows us to check
        # if the ciphertext matches with the associated title, helping prevent against swap attacks.