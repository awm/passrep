Outline of Behaviour
====================

- User's private keys are derived from user's password
- Individual entries encrypted using user's private encryption key
- Access control settings determine read, write, and delegate access to individual entries and groups of entries
- Change procedure:
    - User changes local entry
    - Change notification is encrypted for each user with read access to that entry using secret calculated from modifier's private signing key and reader's public signing key
    - Encrypted change notification pushed on to each user's change queue
    - When user logs in, queued changes are replayed into their local entries
    - Only the latest change may be queued for a particular entry, with the earlier one dropped if a newer one is enqueued
- Access to a particular entry must be granted after an account is created by a user who already has delegate access to the entry
- New user accounts start out with no entries
- There is a fixed admin user which lacks r/w permission but has delegate permission for all entries
- User password change procedure:
    - User's old key is temporarily cached
    - User's new key is calculated
    - Each stored entry in the database is evaluated to see if it was encrypted by this user
        - Entries that match are decrypted using the cached key and then re-encrypted using the new one
    - Each queued entry in the database is evaluated to see if it was encrypted by this user
        - Entries that match are decrypted using the cached key and then re-encrypted using the new one
    - The cached old key is discarded
 - If a user is deleted while other users have pending permission grants from him, the permission grants are re-written to be from admin
 