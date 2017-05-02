# Static Set schema

Example:

    {"camliVersion": 1,
     "camliType": "static-set",

     // Required.
     // May be ordered to unordered, depending on context/needs.  If unordered,
     // it's recommended but not required to sort the blobrefs.
     "members": [
        "digalg-blobref-item1",  // maybe a file?
        "digalg-blobref-item2",  // maybe a directory?
        "digalg-blobref-item3",  // maybe a symlink?
        "digalg-blobref-item4",  // maybe a permanode?
        "digalg-blobref-item5",  // ... don't know until you fetch it
        "digalg-blobref-item6",  // ... and what's valid depends on context
        "digalg-blobref-item7",  // ... a permanode in a directory would
        "digalg-blobref-item8"   // ... be invalid, for instance.
        "digalg-blobref-item9"   // Can also be a static-set, for large directories.
    ]
    }

Note: If a directory has enough children that the resulting static-set blob
      would be larger than the maximum schema blob size, then the children are
      actually spread (recursively, if needed) onto several static-sets. These
      static-sets are in turn the members of the top static-set (the one that is the
      "entries" of the directory schema).

Note: dynamic sets are structured differently, using a permanode and
      membership claim nodes.  The above is just for presenting a snapshot
      of members.
