Archive-Tyd
===========

Archive::Tyd is a simple file archive algorithm that stores multiple files into
an ASCII-based container, with support for compressing or encrypting the member
files using a variety of algorithms.

It is currently a work in progress. See `perldoc Archive::Tyd`.

Front-end Program: tyd
======================

In the `bin` folder is a program named `tyd` which acts as a front-end program
for Archive::Tyd, similar to `zip` or `tar`. Documentation on it is to be
expanded in the future. Example uses for it:

	To create a new archive and give it three files:
	$ tyd -c archive.tyd file1.txt file2.png file3.txt

	To list the contents of a Tyd archive:
	$ tyd -l archive.tyd

	To add an additional file to an archive:
	$ tyd -a archive.tyd file4.txt

	To remove a member file from the archive:
	$ tyd -r archive.tyd file2.txt

	To extract specific files from the archive:
	$ tyd -x archive.tyd file1.txt file3.txt

	To extract all files:
	$ tyd -x archive.tyd

	To use the CipherSaber algorithm to create an encrypted archive:
	$ tyd -A CipherSaber=secret_password archive.tyd file1.txt file2.png

	To extract a file that was encrypted with CipherSaber:
	$ tyd -A CipherSaber=secret_password -x archive.tyd

Note that if you create a file with an algorithm like CipherSaber, you can
extract it without specifying the algorithm again (it will automatically detect
the correct algorithm from the file's headers). But, since CipherSaber requires
a password to encrypt the file, it will prompt for it on standard input in this
event.

LICENSE
=======

Perl Artistic license.

Written by Noah Petherbridge.
