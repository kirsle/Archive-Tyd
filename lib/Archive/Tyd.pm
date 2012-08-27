package Archive::Tyd;

use 5.14.0;
use strict;
use warnings;
use File::Basename;
use File::Temp qw(tempfile tempdir);
use File::Path qw(make_path);
use MIME::Base64;

our $VERSION = '1.00';

=head1 NAME

Archive::Tyd - A simple archiving algorithm.

=head1 SYNOPSIS

  use Archive::Tyd;

  my $tyd = Archive::Tyd->new();

  # Use CipherSaber encryption on the archive.
  $tyd->algorithm("CipherSaber", "big_secret_password");

  # Add some files.
  $tyd->add_file("/etc/passwd");
  $tyd->add_file("/etc/shadow");

  # Add a file but give it a different name in the archive.
  $tyd->add_file("/root/passwords.txt", "/secrets.txt");

  # Add a file by supplying its contents directly.
  $tyd->add_content("/README.txt", "This is an important archive!");

  # Write it to disk.
  $tyd->save("passwords.tyd");

=head1 DESCRIPTION

Archive::Tyd is a simple file archiving algorithm. It supports large archives
(with many files) but not large individual files (subject to the memory
limitations of your system).

Tyd is a simple ASCII-based archive, where the contents of the files are base64
encoded on one line each. It supports various encryption algorithms as well.

=head1 METHODS

=head2 new ([string filename], [hash args])

Create a new Tyd object. If an odd number of arguments are given, the first one
should be the file name of the archive you're working with (the file doesn't
need to exist). If the file already exists, it will automatically be loaded.

Arguments include:

  bool  debug:       Debug mode prints information to STDERR.
  array algorithm:   An algorithm to load at constructor time. Should be an
                     array containing [algorithm_name, arguments]
  bool  no_verifier: When creating encrypted archives, do not include the
                     "verifier" header.

=cut

sub new {
	my $class = shift;
	$class = ref($class) || $class || __PACKAGE__;

	# Odd number of arguments?
	my $file;
	if (scalar(@_) % 2) {
		$file = shift(@_);
	}

	# Get any hash args.
	my (%args) = @_;

	my $self = {
		debug     => $args{debug} || 0,
		filename  => $file,
		checksum  => undef,  # Checksumming algorithm we're using.
		algorithm => undef,  # File mangling algorithm we're using.
		headers   => {},     # Archive headers
		table     => {},     # File table
		handlers  => {},     # Event handlers
		pending   => {       # Pending changes to the archive
			add_file    => [], # Files on disk to add
			remove_file => [], # Files to be removed from archive
			add_content => [], # Files by content to add
		},
		custom_block => {},     # Custom blocks in the archive file
		no_verifier  => $args{no_verifier} || 0,
		fh           => undef,  # File handle
		error        => undef,  # Last error message
	};
	bless ($self, $class);

	# Set the default headers.
	$self->{headers} = {
		name     => "Untitled Archive",
		packager => "Archive::Tyd/$VERSION",
	};

	# Given an algorithm at new-time?
	if (exists $args{algorithm}) {
		if (ref($args{algorithm}) eq "ARRAY") {
			$self->algorithm(@{$args{algorithm}});
		} else {
			$self->algorithm($args{algorithm});
		}
	}

	# Given a file?
	if ($self->{filename} && -e $self->{filename}) {
		$self->load() or return undef;
	}

	return $self;
}

sub d {
	my ($self,$msg) = @_;
	return unless $self->{debug};
	print STDERR $msg, "\n";
}

=head2 void checksum_handler (algorithm)

Load an algorithm for Archive::Tyd to use for calculating checksums. See
L<"CHECKSUMS">. Here, C<algorithm> should either be the name of a checksum
algorithm, or a new instance of an algorithm handler (one that extends
L<Archive::Tyd::Checksum>).

If the algorithm provided is a string and it doesn't contain the characters
C<::> anywhere, it will be assumed to be a built in algorithm under the
C<Archive::Tyd::Checksum::> namespace. Otherwise, you should provide the name
of a Perl package.

=cut

sub checksum_handler {
	my ($self, $name) = @_;
	$self->d("Using checksum algorithm $name");

	# Is it an object?
	if (ref($name)) {
		# Use it straight away.
		$self->{checksum} = $name;
		return;
	}

	# It's a string. Is it a fully qualified package?
	if ($name =~ /::/) {
		my $fname = $name;
		$fname =~ s/::/\//g;
		require "$fname.pm";
		$self->{checksum} = $name->new();
		return;
	}

	# It must be one of our built-ins then.
	my $fname = "Archive/Tyd/Checksum/$name.pm";
	my $ns    = "Archive::Tyd::Checksum::$name";
	require $fname;
	$self->{checksum} = $ns->new();
	return;
}

=head2 void algorithm (algorithm[, args...])

Load an algorithm for Archive::Tyd to use for encoding and decoding the members.
See L<"ALGORITHMS">. Here, C<algorithm> should either be the name of an
algorithm, or a new instance of an algorithm handler (one that extends
L<Archive::Tyd::Algorithm>).

If the algorithm provided is a string and it doesn't contain the characters
C<::> anywhere, it will be assumed to be a built in algorithm under the
C<Archive::Tyd::Algorithm::> namespace. Otherwise, you should provide the name
of a Perl package.

The algorithm object will be created and given the additional C<args> provided
here.

=cut

sub algorithm {
	my ($self, $name, @args) = @_;
	$self->d("Using algorithm $name (@args)");

	# Is it an object?
	if (ref($name)) {
		# Use it straight away.
		$self->{algorithm} = $name;
		$self->{algorithm}->init(@args);
		$self->{headers}->{algorithm} = $self->{algorithm}->name;
		$self->{headers}->{verifier} = encode_base64($self->{algorithm}->encode($name),"")
			unless $self->{no_verifier};
		return;
	}

	# It's a string. Is it a fully qualified package?
	if ($name =~ /::/) {
		my $fname = $name;
		$fname =~ s/::/\//g;
		require "$fname.pm";
		$self->{algorithm} = $name->new(@args); # new will call init
		$self->{headers}->{algorithm} = $self->{algorithm}->name;
		$self->{headers}->{verifier} = encode_base64($self->{algorithm}->encode($self->{algorithm}->name),"")
			unless $self->{no_verifier};
		return;
	}

	# It must be one of our built-ins then.
	my $fname = "Archive/Tyd/Algorithm/$name.pm";
	my $ns    = "Archive::Tyd::Algorithm::$name";
	require $fname;
	$self->{algorithm} = $ns->new(@args);
	$self->{headers}->{algorithm} = $self->{algorithm}->name;
	$self->{headers}->{verifier} = encode_base64($self->{algorithm}->encode($self->{algorithm}->name),"")
		unless $self->{no_verifier};
}

=head2 data header (string header[, string value])

Get or set a header on the archive. Standard headers include C<name>,
C<packager>, and C<algorithm> (but you should use C<algorithm()> to change
that header to make sure the algorithm handler gets loaded).

=cut

sub header {
	my ($self, $name, $value) = @_;

	# Setting a header?
	if (defined $value) {
		# Don't let them change the algorithm.
		if ($name eq "algorithm") {
			return $self->error("You must use algorithm() instead of header() to change the algorithm.");
		}
		$self->{headers}->{$name} = $value;
	}

	return $self->{headers}->{$name};
}

=head2 hashref headers ()

Retrieve all the headers from the archive.

=cut

sub headers {
	my $self = shift;
	return $self->{headers};
}

=head2 string custom_block (string block_name[, string value])

Get or set the value of a custom block from the archive. Custom blocks are
useful for including a signature in the archive. They can include any
arbitrary data.

You cannot set a block named C<header>, C<content>, or any block that begins
with the word C<file:>.

=cut

sub custom_block {
	my ($self, $name, $data) = @_;

	# Setting the block?
	if (defined $data) {
		if ($name =~ /^(header|content|file:.*?)$/) {
			return $self->error("Block name '$name' is a reserved block.");
		}

		$self->{custom_block}->{$name} = [ split(/\x0A/, $data) ]
	}

	if (exists $self->{custom_block}->{$name}) {
		return join("\x0A", @{$self->{custom_block}->{$name}});
	}

	return undef;
}

=head2 bool load ([string filename || filehandle fh])

Load a Tyd archive from a file or filehandle. If you specified an existing
file when you called C<new()>, the file will automatically be opened.

If the archive was saved using a file mangling algorithm, it will be identified
and initialized automatically.

TODO: add some kind of a handler for when an algo requires more info and it
wasn't provided by algorithm()?

=cut

sub load {
	my ($self, $file) = @_;
	$file //= $self->{filename}; #/ syntax highlight fix
	my $fh;

	# Never given a filename?
	if (!defined $file) {
		return $self->error("No filename was provided to load().");
	}

	# Is it a file or file handle?
	if (ref($file) eq "GLOB") {
		$fh = $file;
	}
	elsif (!-e $file) {
		return $self->error("$file: file not found.");
	}
	elsif (!-r $file) {
		return $self->error("$file: no read permission on file.");
	}
	elsif (-d $file) {
		return $self->error("$file: is a directory.");
	}
	else {
		# Save a copy of the name.
		$self->{filename} = $file;
	}

	# Read it.
	unless (defined $fh) {
		open ($fh, "<", $file) or return $self->error("$file: couldn't open file: $@");
	}

	# Collect information.
	my $headers = {}; # File headers read.
	my $table   = {}; # File table read.
	my $first   = <$fh>;

	# Validate the first line.
	$first = trim($first);
	if (index($first, "TYD2") != 0) {
		return $self->error("$file: not a TYD2 archive.");
	}
	my ($algorithm, $hash) = ($first =~ /^TYD2:(.+?):(.+?)$/);
	if (!defined $algorithm || !defined $hash) {
		return $self->error("$file: missing or corrupt checksum line.");
	}

	# Load the checksum handler to be sure we have it.
	$self->_autoload_checksum($algorithm);

	# Checksum it.
	my $ok = $self->{checksum}->verify($hash, $fh);
	if (not $ok) {
		return $self->error("$file: checksum test has failed.");
	}

	# Reset the file handle for reading.
	seek($fh, 0, 0);
	$first = <$fh>; # Take off the first line again.

	# Read through the file.
	my $section;
	my @crypt_table; # encrypted file table?
	while (my $line = <$fh>) {
		$line = trim($line);
		next if $line =~ /^;/; # Comment lines
		next unless length $line;

		if ($line =~ /^\[(.+?)\]$/) {
			# Section header!
			$section = $1;

			# Break at the [content] block.
			last if $section eq "content";

			next;
		}

		# Deal with different sections.
		if ($section eq "header") {
			# Headers.
			my ($what,$is) = split(/=/, $line, 2);
			$what = trim($what); $is = trim($is);
			
			$self->d("HEADER: $what = $is");
			$headers->{$what} = $is;
		}
		elsif ($section =~ /^file:(.+?)$/i) {
			my $fn = $1;
			my ($what,$is) = split(/=/, $line, 2);
			$what = trim($what); $is = trim($is);

			$table->{$fn}->{$what} = $is;
		}
		elsif ($section eq "file-table") {
			push @crypt_table, $line;
		}
		else {
			# Custom block.
			if (!exists $self->{custom_block}->{$section}) {
				$self->{custom_block}->{$section} = [];
			}
			push @{$self->{custom_block}->{$section}}, $line;
		}
	}

	# Did the headers tell us about an algorithm?
	if (!defined $self->{algorithm} && exists $headers->{algorithm}) {
		# Load it.
		$self->algorithm($headers->{algorithm});
	}

	# If there's an algorithm AND a verifier, verify it.
	if (defined $self->{algorithm} && exists $headers->{verifier} && !$self->{no_verifier}) {
		my $verifier = decode_base64($headers->{verifier});
		my $check = $self->{algorithm}->decode($verifier);
		if ($check ne $self->{algorithm}->name) {
			# Verification failed.
			return $self->error("The decryption verifier has failed. Did you provide the wrong key?");
		}
	}

	# Is the file table encrypted?
	if (scalar(@crypt_table)) {
		# Try to decipher it.
		$self->d("The file table is encrypted!");
		if (defined $self->{algorithm}) {
			my $tabledata = $self->{algorithm}->decode(decode_base64(join("\n",@crypt_table)));

			# Collect files out of it.
			my @lines = split(/\n/, $tabledata);
			my $filename = '';
			foreach my $line (@lines) {
				$line = trim($line);
				next if $line =~ /^;/; # Comment lines
				next unless length $line;

				if ($line =~ /^\[file:(.+?)\]$/i) {
					$filename = $1;
					next;
				}
				if ($filename) {
					my ($what, $is) = split(/=/, $line, 2);
					$what = trim($what); $is = trim($is);
					$table->{$filename}->{$what} = $is;
				}
			}

			if (!$filename) {
				# No filename found?
				return $self->error("No files found in the decrypted file table!");
			}
		}
		else {
			return $self->error("The file table is encrypted, and no algorithm is available to decode it.");
		}
	}

	# Save the information we found.
	$self->{headers} = $headers;
	$self->{table}   = $table;
	$self->{fh}      = $fh;

	return 1;
}

=head2 bool add_content (string filename => bin content, ...)

Add a file to the archive by specifying the contents directly. C<filename> is
the file path for the file to be added, beginning with C</> for the root of
the archive (for example, C</README.txt>). C<content> is the file's contents.

Multiple files may be added with one call.

Note that files added this way are put into a queue of pending changes to the
archive, and thus will be kept in memory until the archive is written.

=cut

sub add_content {
	my ($self, %add) = @_;

	# Add to the pending queue.
	foreach my $fn (keys %add) {
		# Validate the file format.
		if ($fn !~ /^\//) {
			return $self->error("Filenames must begin with a /");
		}
		elsif ($fn =~ /[^A-Za-z0-9\_\.\-\/\: \@\+\#\$]/) {
			return $self->error("$fn: contains invalid characters.");
		}
		push @{$self->{pending}->{add_content}}, [ $fn, $add{$fn} ];
	}

	return 1;
}

=head2 bool add_file (string filename => string archivename, ...)

Add an existing file to the archive by name. The file is added to a queue
to be written next time the archive is saved.

If you only pass a single argument, it will get the same name in the
archive. Otherwise pass a key/value pair of the file name on disk and
its filename in the archive (in the archive, the filename must begin
with a /).

Multiple files may be added at a time, but they must be passed in hash
format in this case.

=cut

sub add_file {
	my ($self, @files) = @_;

	my %add;
	if (scalar(@files) == 1) {
		$add{$files[0]} = $files[0];
	}
	else {
		%add = @files;
	}

	foreach my $file (keys %add) {
		# Validate the file format.
		if ($add{$file} !~ /^\//) {
			return $self->error("Filenames must begin with a /");
		}
		elsif ($add{$file} =~ /[^A-Za-z0-9\_\.\-\/\: \@\+\#\$]/) {
			return $self->error("$add{$file}: contains invalid characters.");
		}
		$self->d("Add to add_file queue: $file => $add{$file}");
		push @{$self->{pending}->{add_file}}, [ $file, $add{$file} ];
	}

	return 1;
}

=head2 int remove_file (string archivename, ...)

Remove files from the archive. The files are added to a queue to be removed the
next time the archive is saved. Pass in a list of multiple files to delete many
with one call.

Returns the number of files that were removed (so, for example, if you provide a
file name that doesn't exist in the archive, this will return less than the
number of files given). An undef return value indicates an error.

=cut

sub remove_file {
	my ($self, @files) = @_;

	my $removed = 0;
	foreach my $file (@files) {
		# Exists?
		if (exists $self->{table}->{$file}) {
			push @{$self->{pending}->{remove_file}}, $file;
			$removed++;
		}
	}

	return $removed;
}

=head2 array list ()

List all the files within the archive. Doesn't include pending files.

=cut

sub list {
	my $self = shift;

	return sort keys %{$self->{table}};
}

=head2 bool extract ([string file => string filepath])

Extract files from the archive. If given an odd number of arguments, it will
extract just the file mentioned and give it the same file path on disk,
relative to the current working directory. Otherwise, provide a hash of
key/value pairs to map the files in the archive to files on the disk.

If given no arguments at all, all files will be extracted relative to the
current working directory.

=cut

sub extract {
	my ($self, @args) = @_;

	my %extract;

	if (scalar(@args) == 0) {
		# Extract ALL files.
		my @list = $self->list();
		foreach my $name (@list) {
			$self->extract($name);
		}
		return 1;
	}
	elsif (scalar(@args) == 1) {
		# Extracting a single file.
		my $file = $args[0];
		$file =~ s/^\//.\//g; # Change / to ./ for relative-to-current-directory.
		$extract{ $args[0] } = $file;
	}
	else {
		# Extracting multiple files at once.
		%extract = @args;
	}

	# Extract them!
	foreach my $file (keys %extract) {
		$self->d("$file -> $extract{$file}");

		# Create the directory tree here.
		my $dir = dirname($extract{$file});
		if (!-d $dir) {
			$self->d("mkpath: $dir");
			make_path($dir);
		}

		# Write the file.
		my $bin = $self->cat($file) or return undef; # Error is set in cat()
		open (my $fh, ">", $extract{$file}) or return $self->error("Can't write to $extract{$file}: $@");
		binmode($fh);
		print {$fh} $bin;
		close ($fh);
	}

	return 1;
}

=head2 data cat (string file)

Slurp the data from a file that exists in the archive. This doesn't work for
pending files. If a file mangling algorithm is used (see L<"ALGORITHMS">), this
method will automatically decode it for you.

=cut

sub cat {
	my ($self, $file) = @_;

	# Exists?
	if (!exists $self->{table}->{$file}) {
		return $self->error("cat: $file not found in the archive.");
	}

	# Get its index number.
	my $index = $self->{table}->{$file}->{index};
	$self->d("cat $file (index $index)");

	# Find it.
	my $fh = $self->{fh};
	seek($fh, 0, 0);
	my $inContent = 0;
	my $i         = 0;
	my $data;
	while (my $line = <$fh>) {
		$line = trim($line);
		if ($line eq "[content]") {
			$inContent = 1;
			next;
		}

		# Seeing the file contents?
		if ($inContent) {
			if ($i == $index) {
				# Found it!
				$self->d("Found file data at index $i");
				$data = $line;
				last;
			}
			$i++; # Keep searching!
		}
	}

	# No data?
	if (!defined $data) {
		return $self->error("cat: no data found for file $file");
	}

	# Base64 decode it to our (probably mangled) binary blob.
	$data = decode_base64($data);

	# De-mangle it?
	if (defined $self->{algorithm}) {
		$self->d("Decoding the data with " . $self->{algorithm}->name);
		$data = $self->{algorithm}->decode($data);
	}

	return $data;
}

=head2 bool save ([string filename || filehandle fh][, hash options])

Write the changes back to the archive. This will flush all pending writes,
call any event handlers for encryption of file contents, etc.

If a file mangling algorithm is used (see L<"ALGORITHMS">), this will
automatically encode the member files when saving the archive to disk.

The resulting archive format will use the Line Feed character (C<\n>,
C<\x0A>) at the ends of the lines, regardless of your host platform.

Options include:

=over 4

=item str checksum = SHA1

The checksum algorithm to use. If not provided, the checksum algorithm
of the original archive is used (if applicable), otherwise the default
of "SHA1" is used.

The checksum algorithm is used both for the archive itself and for
individual member files inside the archive.

=item bool signature = false

Use the signing features of the encryption algorithm to include a
signature in the resulting archive. This option may only be used when
the encryption algorithm provides the "signing" option.

=item bool encrypt = true

Use the encryption features of the encryption algorithm. By default, this
option is enabled (provided you're using an algorithm that supports
encryption). However, if you use the C<signature> option, then encrypting
is turned off by default and you will need to explicitly define the
C<encrypt> option yourself.

=item bool file_table = false

Use the encryption features I<on the file table itself>. With this enabled,
the resulting archive won't have a human readable file table; this will be
encrypted (using your encryption algorithm) and includes as a block section
labeled "C<[file-table]>". This will then need to be decrypted before doing
any operations such as C<list()> on the archive in the future.

=back

=cut

sub save {
	my ($self, $file, %opts) = @_;
	$file //= $self->{filename}; #/ syntax highlight fix
	my $fh;

	# Write options.
	my $algo = $opts{checksum} || (defined $self->{checksum} ? $self->{checksum}->name() : "SHA1");

	# Load the checksum handler to be sure we have it.
	$self->_autoload_checksum($algo);

	# Problems?
	if (ref($file) eq "GLOB") {
		$fh   = $file;
		$file = $self->{filename};
	}
	if (!defined $file) {
		return $self->error("No file name was given for writing.");
	}

	# Validation.
	if (-e $file && !-w $file) {
		return $self->error("$file: no write permission on file.");
	}
	elsif (-d $file) {
		return $self->error("$file: is a directory.");
	}

	# Encryption is on by default, unless signature is used.
	if (!exists $opts{encrypt}) {
		if ($opts{signature}) {
			$opts{encrypt} = 0;
		}
		else {
			$opts{encrypt} = 1;
		}
	}

	# Write to a temp file first.
	my ($th,$tempfile) = tempfile();
	$self->d("Writing to temp file: $tempfile");

	# Print the headers.
	print {$th} "\x0A[header]\x0A";
	foreach my $key (keys %{$self->{headers}}) {
		# If the algorithm is one of our built-ins, don't include the fully qualified part.
		if ($key eq "algorithm" && $self->{headers}->{$key} =~ /^Archive::Tyd::Algorithm::/) {
			$self->{headers}->{$key} =~ s/^Archive::Tyd::Algorithm:://;
		}
		print {$th} "$key=$self->{headers}->{$key}\x0A";
	}

	# File indexes for newly added files.
	my $index = 0;
	my @newfiles;  # Base64 encoded new files.

	# First, make a quick map of the names of files we're adding. This way the
	# user can re-add existing files, and we won't stomp on their changes when
	# extracting the existing files.
	my %new_files = ();
	foreach my $add (@{$self->{pending}->{add_file}}) {
		$new_files{ $add->[1] } = 1;
	}
	foreach my $add (@{$self->{pending}->{add_content}}) {
		$new_files{ $add->[0] } = 1;
	}
	foreach my $rm (@{$self->{pending}->{remove_file}}) {
		# Yes, removed files are "added" files (they just won't be added back).
		$new_files{$rm} = 1;
	}

	# If we're modifying an existing archive, extract it all to temp and start
	# over from scratch.
	if (scalar keys %{$self->{table}} > 0) {
		my $tempdir = tempdir(CLEANUP => 1);
		$self->d("Extracting all current members to temp dir");

		foreach my $name (keys %{$self->{table}}) {
			# Skip if we're re-adding this one later.
			if (exists $new_files{$name}) {
				$self->d("Do not extract $name: re-adding it!");
				next;
			}

			# Use its checksum as file name.
			my $tmpname = $self->{table}->{$name}->{checksum};
			$self->extract($name, "$tempdir/$tmpname");

			# Re-add it.
			$self->add_file("$tempdir/$tmpname" => $name);
		}
	}
	$self->{table} = {}; # Blank out the file table.

	# Add files from disk.
	foreach my $add (@{$self->{pending}->{add_file}}) {
		my ($disk, $name) = @{$add};
		$self->d("Add to archive: $name (from file: $disk)");

		# Initialize its file table entry.
		if (!exists $self->{table}->{$name}) {
			$self->{table}->{$name} = {};
		}
		my $tab = $self->{table}->{$name};

		# Read the file from disk.
		local $/;
		open (my $ah, "<", $disk) or return $self->error("Can't add $disk to archive - couldn't read file: $@");
		binmode($ah);

		# Populate file attributes in the table.
		my @stat = stat($disk);
		$tab->{index}    = $index++; # Choose the index in the [content] section.
		$tab->{checksum} = $self->{checksum}->digest($ah) or return $self->error();
		$tab->{atime}    = $stat[8];
		$tab->{mtime}    = $stat[9];
		$tab->{ctime}    = $stat[10];
		$tab->{chmod}    = $stat[2];

		# Now slurp the contents.
		seek($ah, 0, 0);
		my $slurp = <$ah>;

		# Get the original file size.
		my $fsize = length($slurp);

		# Mangle the data?
		if ($opts{encrypt} && defined $self->{algorithm}) {
			$self->d("Encoding the data with " . $self->{algorithm}->name);
			$slurp = $self->{algorithm}->encode($slurp);
		}

		# Base64 encode it and take its new size.
		$slurp = encode_base64($slurp,"");
		my $asize = length($slurp);
		$self->d("File size $fsize -> $asize");
		
		# Store the file sizes.
		$tab->{size}  = $fsize;
		$tab->{asize} = $asize;

		# Add it to the new file buffer.
		push @newfiles, $slurp;

		# Done with the file!
		close($ah);
	}

	# Add files from content buffers.
	foreach my $add (@{$self->{pending}->{add_content}}) {
		my ($name, $content) = @{$add};
		$self->d("Add to archive: $name (from provided content)");

		# Initialize its file table entry.
		if (!exists $self->{table}->{$name}) {
			$self->{table}->{$name} = {};
		}
		my $tab = $self->{table}->{$name};

		# Populate file attributes in the table.
		$tab->{index}    = $index++; # Choose the index in the [content] section.
		$tab->{checksum} = $self->{checksum}->digest($content) or return $self->error();

		# Get the original file size.
		my $fsize = length($content);

		# Mangle the data?
		if ($opts{encrypt} && defined $self->{algorithm}) {
			$self->d("Encoding the data with " . $self->{algorithm}->name);
			$content = $self->{algorithm}->encode($content);
		}

		# Base64 encode it and take its new size.
		$content = encode_base64($content,"");
		my $asize = length($content);
		$self->d("File size $fsize -> $asize");

		# Store the file sizes.
		$tab->{size}  = $fsize;
		$tab->{asize} = $asize;

		# Add it to the new file buffer.
		push @newfiles, $content;
	}

	# Write the file table. Are we encrypting the file table?
	if ($opts{file_table} && defined $self->{algorithm}) {
		$self->d("Encoding the file table with " . $self->{algorithm}->name);
		my $table = $self->file_table();
		$table = encode_base64($self->{algorithm}->encode($table));
		$table =~ s/[\x0D\x0A]+$//g;
		print {$th} "\x0A[file-table]\x0A"
			. $table . "\x0A";
	}
	else {
		my $table = $self->file_table();
		print {$th} "\x0A$table\x0A";
	}

	# Are we signing?
	if ($opts{signature}) {
		# Can our algorithm sign?
		if (defined $self->{algorithm} && $self->{algorithm}->can_sign()) {
			$self->d("Signing the file table...");

			# Get the file table and sign it.
			my $table = $self->file_table();
			my $signature = encode_base64($self->{algorithm}->sign($table));
			$self->custom_block("signature", $signature);
		}
		else {
			warn "Unable to sign the file table: algorithm doesn't support signatures!";
		}
	}

	# Write custom blocks.
	foreach my $block (sort keys %{$self->{custom_block}}) {
		print {$th} "\x0A[$block]\x0A"
			. join("\x0A", @{$self->{custom_block}->{$block}}) . "\x0A";
	}

	# Write the contents.
	print {$th} "\x0A[content]\x0A";
	foreach my $add (@newfiles) {
		print {$th} "$add\x0A";
	}

	# Generate the checksum.
	seek($th, 0, 0);
	my $hash = $self->{checksum}->digest($th) or return $self->error();
	$self->d("Calculated checksum: $hash");

	# Write the final archive.
	if (!defined $fh) {
		open ($fh, ">", $file) or return $self->error("$file: couldn't open file for writing: $@");
	}
	seek($th, 0, 0);
	print {$fh} join(":", "TYD2", $algo, $hash), "\x0A";
	while (<$th>) {
		print {$fh} $_;
	}

	# Clean up.
	close ($th);
	close ($fh);

	return 1;
}

=head2 bool verify ([string membername])

Verify the integrity of the archive or a member file in the archive.

If the archive is signed (e.g. has a C<signature> custom block), the signature
will be verified using the encryption algorithm that the file is using.

If given a specific file name, the checksum of the file will be verified.

This method doesn't verify the checksum of the I<archive file> itself; this was
taken care of on the call to C<load()>.

If any verification fails, this method returns undef and the error description
is available from C<error()>. Otherwise, this returns 1.

=cut

sub verify {
	my ($self, $file) = @_;

	# Are we verifying an individual file?
	if (defined $file) {
		# Get its data.
		if (!exists $self->{table}->{$file}) {
			return $self->error("$file: not found in file table.");
		}

		$self->d("Verify member file: $file");
		my $checksum = $self->{table}->{$file}->{checksum};
		my $data     = $self->cat($file);
		
		# Validate.
		if ($self->{checksum}->verify($checksum, $data)) {
			return 1;
		}
		else {
			return $self->error("$file: checksum verification has failed.");
		}
	}

	# We're verifying the entire archive. Is there a signature block?
	if (my $signature = $self->custom_block("signature")) {
		$self->d("Verify signature on archive.");
		if (defined $self->{algorithm} && $self->{algorithm}->can_sign()) {
			# Verify it.
			my $table = $self->file_table();
			if ($self->{algorithm}->verify(decode_base64($signature), $table)) {
				return 1;
			}
			else {
				return $self->error("Signature check has failed.");
			}
		}
		else {
			return $self->error("The algorithm in use doesn't support signatures.");
		}
	}

	# Verify the integrity of each member file.
	foreach my $file (keys %{$self->{table}}) {
		my $ok = $self->verify($file);
		if (!$ok) {
			return undef;
		}
	}

	return 1;
}

=head2 string file_table ()

Retrieve the file table as a string. This returns the file table in a consistent
way (sorted alphabetically, etc.) which also includes their index numbers.

This method is useful for signing algorithms that wish to create a signature
based on the file table (which will be quicker to compute for large archives
than a signature based on the file data).

The string returned from this method will always use the Line Feed character
(C<\n>, C<\x0A>) to separate the lines, regardless of your host platform.

=cut

sub file_table {
	my $self = shift;

	my @lines;
	foreach my $file (sort keys %{$self->{table}}) {
		push (@lines, "[file:$file]");
		foreach my $key (sort keys %{$self->{table}->{$file}}) {
			push (@lines, "$key=$self->{table}->{$file}->{$key}");
		}
		push (@lines, "");
	}

	if ($lines[-1] eq "") {
		pop(@lines);
	}

	return join("\x0A", @lines);
}

=head2 string error ()

Retrieve the last error message given. When a function returns undefined, call
C<error()> to see what the reason was.

=cut

sub error {
	my ($self, $error) = @_;

	# Setting the error message?
	if ($error) {
		$self->{error} = $error;
		$self->d("Set error message: $self->{error}");
		return undef;
	}

	return $self->{error};
}

=head1 ALGORITHMS

Archive::Tyd supports what I call "file mangling algorithms". These are pieces
of code that will encode and decode the contents of your archive's member files.
They can either compress or encrypt the file data.

The file mangling algorithms extend the class L<Archive::Tyd::Algorithm>. See
the included examples, CipherSaber and RSA.

=head1 FILE FORMAT

The file format is simple and is ASCII-based. If viewed in a text editor it
resembles an INI file. Archive files are always written using the Line Feed
(C<\n>, C<\x0A>) as the end of line character, regardless of the host platform.
This is essential so that checksumming and code signing can work properly.

=over 4

=item Checksum Line

The first line of the file is the checksum for the remainder of the file. An
example:

  TYD2:SHA1:22596363b3de40b06f981fb85d82312e8c0ed511

The first four characters will always be C<TYD2>, as this specifies the version
of the Tyd algorithm. The checksum encodings C<MD5> and C<SHA1> are
supported by the module, but you may define your own algorithm with a handler.
The default algorithm used is SHA1.

The checksum is a hash of I<all the lines> of the file, excluding the checksum
line itself. When loading a file from disk, this checksum line is validated
against the archive's contents, and it's considered an error when it doesn't
match.

=item Header Section

The C<[header]> section contains the header information for the archive. These
are arbitrary key/value pairs, and some of the typical keys are as follows:

  str name:      A short name for the archive.
  str packager:  The packager's name and/or e-mail address.
  str comment:   A description of the package.
  str algorithm: The algorithm used to encode the files
  str verifier:  If an algorithm is used, this is a self-verification check.

If the algorithm in use is a built-in one (under the C<Archive::Tyd::Algorithm>
namespace), then its value will just be the algorithm name, e.g. C<CipherSaber>.
Otherwise it will be the name of a fully qualified Perl module.

The C<verifier> header is used as a self verification test for the algorithm.
To calculate the verifier, the algorithm is asked to encode its own name,
for example CipherSaber will encode the word "CipherSaber" using your
encryption key. To verify this header, the algorithm is asked to decode the
C<verifier> and see if it results in the algorithm's own name. If you don't
like this behavior, supply the C<no_verifier> option to C<new()> and it won't
be written to the archive file.

=item File Sections

Each file in the archive will have its own section. The sections will be named
like C<[file:X]>, where X is the path to the file (for example, "/README" or
"/lib/Archive/Tyd.pm"). In each section will be key/value pairs containing
attributes of the file. These fields are arbitrary, but the following are
typical:

  int index:    The line number in the [content] section for the file's contents
  str checksum: A checksum line for the file (ex. MD5:...)
  int atime:    Access time on the file.
  int ctime:    Created time or changed time on the file.
  int mtime:    Modified time on the file.
  int chmod:    Chmod permissions on the file (for ex. 755).
  int size:     Real file size (when extracted)
  int asize:    Archive file size (size of [content] section)

The only absolutely required fields are C<index> and C<checksum>.

=item Custom Sections

Some encryption algorithms may require their own custom sections. For example,
with an RSA encryption algorithm, a C<[signature]> section may be useful. A
section can be pulled from the archive by using the C<custom_section()> method.

=item Content Section

The C<[content]> section is where the contents of the files lie. This section
can contain no blank lines. Each line will be a Base64 encoded string of the
contents of one of the files in the archive. The line numbers are referred to
by index from the File Sections.

=back

=cut

# string trim (string)
# Removes all types of line breaks from a line,
# and removes spaces from both ends.
sub trim {
	my $line = shift;
	$line =~ s/[\x0D\x0A]+//g;
	$line =~ s/^\s+//g;
	$line =~ s/\s+$//g;
	return $line;
}

# Automatically load a checksum handler by name, e.g. SHA1.
sub _autoload_checksum {
	my ($self, $checksum) = @_;

	# Not if we're already using this one.
	if (ref($self->{checksum}) && $self->{checksum}->name() eq $checksum) {
		return;
	}

	# Apply the checksum handler.
	$self->checksum_handler($checksum);
}

=head1 SEE ALSO

L<Archive::Tyd::Algorithm> for implementing custom algorithms, or
L<Archive::Tyd::Checksum> for implementing custom checksums.

=head1 LICENSE

This module is released under the same terms as Perl itself.

=head1 AUTHOR

Noah Petherbridge, http://www.kirsle.net/

=cut

1;
