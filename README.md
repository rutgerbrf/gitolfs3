gitolfs3
========

Gitolfs3 is a very simple Git LFS server.

It needs to do one thing: provide me with a personal Git LFS server that I can
run on my VPS. It seems to be doing an okay job at it so far.

The name 'Gitolfs3' started as some kind of concoction of Gitolite, LFS and S3.
These days, this project has nothing to do with Gitolite because I don't use
Gitolite anymore. (It was too extensive for my use case, and I prefer to keep
the complexity of my system down as much as possible.)

Currently, it has the following features:

- Storage with S3-compatible services (at the moment of writing, I am using
  Scaleway Object Storage for this purpose)
- Git LFS Batch API support. Only the basic transfer adapter is supported. Only
  SHA256 Object IDs (OIDs) are supported.
- `git-lfs-authenticate` is provided for authentication over SSH. File transfer
  over SSH using `git-lfs-transfer` is not supported.
- A Git shell is provided so that I can stay sane. (I don't recall 100%, but I
  believe this was nice when wanting to push to some ssh://git@asdf/blabla.git
  repo without having to type `/srv/git` before the repo name. And I don't want
  to have to use something like Gitolite.)
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

This program, as it is, solely serves my needs. Although I may occasionally add
some features or perform some cleanups (especially the server still requires
some), I have no interest in making this program work for people with different
use cases than me. In case you want to use this software, feel free to, but
expect that you will basically have to 'make it your own'. If you have a
burning question or find a security vulnerability, feel free to email me. I'm
sure you'll manage to find my email address somewhere.
