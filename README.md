Gitolfs3: a very simple Git LFS server
======================================

[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)

Gitolfs3 is the Git LFS server that runs on my VPS. It uses an S3-compatible
service as backing storage. It seems to be working fine up until now, but
doesn't get too much use (so the primary reason for breakage is me being too
lazy to refresh credentials).

The name 'Gitolfs3' started as a portmanteau of Gitolite, Git LFS and S3. These
days, this project has nothing to do with Gitolite, because I don't use
Gitolite anymore. (It was too extensive for my use case, and I prefer to keep
the complexity of my system down as much as possible.)

Currently, it has the following features:

- Storage with S3-compatible services (at the moment of writing, I am using
  Scaleway Object Storage).
- Git LFS Batch API support. Only the basic transfer adapter with
  SHA256 Object IDs (OIDs) is supported.
- `git-lfs-authenticate` is provided for authentication over SSH. File transfer
  over SSH using `git-lfs-transfer` is not supported.
- A Git shell is provided so that I can stay sane. (I don't recall 100%, but I
  believe this was nice when wanting to push to some ssh://git@asdf/blabla.git
  repo without having to type `/srv/git` before the repo name. And I don't want
  to have to use something like Gitolite.)
- No requirement for any kind of persistent or temporary storage for tokens.
  Instead, user authentication/authorization between `git-lfs-authenticate` and
  the Gitolfs3 server is done using HMAC(-SHA256) MACs.
- Limiting unauthenticated public downloads on a per-hour basis. Storage is
  required for this. (This feature is implemented pretty badly.)
- Public/private repos based on the `git-daemon-export-ok` file in the bare
  repo. (I have a very particular setup in which this is desirable.)
    - Downloads for files in public repositories are 'proxied' through the
      Gitolfs3 server, at least when accessed from the public internet.
    - Unauthenticated users accessing the service over a private network
      (authorized by `X-Fowarded-Host`) can access all repositories. Downloads
      for these users are not proxied: instead, they are directed to pre-signed
      S3 download URLs.
    - Authenticated users can download and upload for all repositories,
      regardless of how they access the service.

This program, as it is, works well enough for me. Although I may occasionally
add some features or perform some cleanups, I don't really have the time to
make this program work for different use cases than mine. Do feel free to email
me if you have any questions.

Nice-to-have features that I may implement at some point, when I feel a need
to:

- No namespacing on S3. (So the same big file in two repositories would only be
  stored on S3 once.)
- Any kind of file deletion/garbage collection. You need to do this manually
  right now.
- Resuming downloads.
