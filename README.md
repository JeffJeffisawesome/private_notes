The backend implementation of a private Note Taking app.

The user initializes their notes database with a password.
They can also:
set(title, note): makes a new notes entry
get(title): get the note with the corresponding title
remove(title): remove the note with the corresponding title

When the user is done taking notes, they use the dump() function, which spits out the serialized notes database, along with a checksum.
To access the notes later, the user initializes the database, but this time with parameters (password, serialized data, checksum). Any tampering with the serialized data or checksum will be detected.
