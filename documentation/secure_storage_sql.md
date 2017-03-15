# SQL DB Secure Storage

## Introduction

This document describes the SQL DB secure storage in OP-TEE, which is enabled
by setting CFG_SQL_FS=y. Trusted Applications may use this implementation by
passing a storage ID equal to TEE_STORAGE_PRIVATE_SQL, or TEE_STORAGE_PRIVATE
if CFG_REE_FS and CFG_RPMB_FS are disabled.
With this filesystem, the secure object are stored as individual files in a
SQLite database (which is a file by itself in the REE filesystem).
This implementation may be viewed as a simplified version of the REE FS, because
it uses a single file per persistent object. This is possible because SQLite has
a transaction API which allows atomic updates (and rollback in case of error).

Files are created in the database by the **libsqlfs** library [[1]](#libsqlfs).
For details about **SQLite**, please refer to [[2]](#SQLite).

The architecture is depicted below.

```
            NORMAL WORLD           :            SECURE WORLD
                                   :
 U        tee-supplicant           :        Trusted application
 S          (sql_fs.c)             :        (secure storage API)
 E      libsqlfs      ^            :                  ^
 R       SQLite       |            :~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~:                  v
 K         |          |            :               OP-TEE
 E         v          v            :         (tee_svc_storage.c)
 R  REE filesystem  OP-TEE driver  :  (tee_sql_fs.c, tee_fs_key_manager.c)
 N                           ^     :                  ^
 E                           |     :                  |
 L                           |     :                  |
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~
                             v                        v
                           Secure monitor / EL3 firmware
```

## The Secure Storage API

This part is common with the other filesystems. The interface between the
system calls in [core/tee/tee_svc_storage.c](../core/tee/tee_svc_storage.c) and
the SQL filesystem is the **tee_file_operations** structure `sql_fs_ops`.

## The SQL filesystem

The secure side of the SQL FS implementation is mostly in
[core/tee/tee_sql_fs.c](../core/tee/tee_sql_fs.c). This file maps the
operations in `sql_fs_ops` such as `open`, `truncate`, `read`, `write`
and so on, to similar operations on a file that is a container for
the encrypted data and associated meta-data. This container is created and
manipulated by `tee-supplicant` on request from the secure OS. Its logical
layout is similar to REE FS except that there's only a single version of
each field as atomic updates are ensured by **libsqlfs** instead.

How this file is stored in the SQLite database is private to **libsqlfs**. From
the point of view of OP-TEE, it is a byte-addressable linear file on which
atomic updates can be performed through a standard interface (`open`,
`truncate`, `read`, `write`...) with the addition of `begin_transaction`
and `end_transaction`.

## Encryption

The encryption is the same as for REE FS, so you can find more details in the
encryption section of [secure_storage.md](secure_storage.md). Bear in mind that
the only difference lies in the data storage: one single file for the SQL
implementation, versus multiple `meta` and `block` files for the REE FS.

## References

- <a name="libsqlfs"></a>[1] **libsqlfs**
[http://www.nongnu.org/libsqlfs/](http://www.nongnu.org/libsqlfs/),
[https://github.com/guardianproject/libsqlfs](https://github.com/guardianproject/libsqlfs)
- <a name="SQLite"></a>[2] **SQLite** [https://www.sqlite.org/](https://www.sqlite.org/)
